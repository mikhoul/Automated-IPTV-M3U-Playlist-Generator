import requests
import json
import os
import re
from urllib.parse import urlparse
from collections import defaultdict
from datetime import datetime
import pytz
import concurrent.futures
import threading
import logging
from bs4 import BeautifulSoup

# ← CHANGEMENT : Activation des logs DEBUG pour diagnostic
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def get_server_geolocation():
    """Obtenir la géolocalisation du serveur GitHub Actions."""
    try:
        # Obtenir l'IP publique du serveur
        ip_response = requests.get('https://api.ipify.org?format=json', timeout=10)
        server_ip = ip_response.json()['ip']
        
        # Obtenir la géolocalisation via ipapi.co (gratuit, 1000/jour)
        geo_response = requests.get(f'https://ipapi.co/{server_ip}/json/', timeout=10)
        geo_data = geo_response.json()
        
        location_info = {
            'ip': server_ip,
            'country': geo_data.get('country_name', 'Unknown'),
            'country_code': geo_data.get('country_code', 'Unknown'),
            'region': geo_data.get('region', 'Unknown'), 
            'city': geo_data.get('city', 'Unknown'),
            'org': geo_data.get('org', 'Unknown'),
            'timezone': geo_data.get('timezone', 'Unknown')
        }
        
        logging.info("=" * 60)
        logging.info(f"SERVER GEOLOCATION DETECTED:")
        logging.info(f"Testing from: {location_info['city']}, {location_info['region']}, {location_info['country']} ({location_info['country_code']})")
        logging.info(f"Server IP: {location_info['ip']}")
        logging.info(f"ISP/Organization: {location_info['org']}")
        logging.info(f"Timezone: {location_info['timezone']}")
        logging.info("=" * 60)
        
        return location_info
        
    except Exception as e:
        logging.warning(f"Failed to get server geolocation: {e}")
        logging.info("Proceeding without geolocation information...")
        return None

class M3UCollector:
    def __init__(self, country="Mikhoul", base_dir="LiveTV", check_links=True, excluded_groups=None):
        self.channels = defaultdict(list)
        self.default_logo = "https://buddytv.netlify.app/img/no-logo.png"
        self.seen_urls = set()
        self.url_status_cache = {}
        self.output_dir = os.path.join(base_dir, country)
        self.lock = threading.Lock()
        self.check_links = check_links  # Toggle link checking
        self.excluded_groups = excluded_groups or []  # Liste des groupes à exclure
        self.skipped_non_http_count = 0  # Compteur des URLs non-HTTP ignorées
        os.makedirs(self.output_dir, exist_ok=True)

    def fetch_content(self, url):
        """Fetch content (M3U or HTML) with streaming."""
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        
        try:
            with requests.get(url, stream=True, headers=headers, timeout=10) as response:
                response.raise_for_status()
                lines = [line.decode('utf-8', errors='ignore') if isinstance(line, bytes) else line for line in response.iter_lines()]
                content = '\n'.join(lines)
                if not lines:
                    logging.warning(f"No content fetched from {url}")
                else:
                    logging.info(f"Fetched {len(lines)} lines from {url}")
                return content, lines
        except requests.RequestException as e:
            logging.error(f"Failed to fetch {url}: {str(e)}")
            return None, []

    def extract_stream_urls_from_html(self, html_content, base_url):
        """Extract streaming URLs from HTML."""
        if not html_content:
            return []
        
        soup = BeautifulSoup(html_content, 'html.parser')
        stream_urls = set()
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            parsed_base = urlparse(base_url)
            parsed_href = urlparse(href)
            if not parsed_href.scheme:
                href = f"{parsed_base.scheme}://{parsed_base.netloc}{href}"
            
            if (href.endswith(('.m3u', '.m3u8')) or 
                re.match(r'^https?://.*\.(ts|mp4|avi|mkv|flv|wmv)$', href) or 
                'playlist' in href.lower() or 'stream' in href.lower()):
                if not any(exclude in href.lower() for exclude in ['telegram', '.html', '.php', 'github.com', 'login', 'signup']):
                    stream_urls.add(href)
        
        logging.info(f"Extracted {len(stream_urls)} streaming URLs from {base_url}")
        return list(stream_urls)

    def check_link_active(self, url, channel_name="Unknown Channel", timeout=9):
        """Check if a link is active, with specialized HLS validation."""
        
        # Headers optimisés pour les flux vidéo et Akamai
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/vnd.apple.mpegurl, application/x-mpegURL, application/octet-stream, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'cross-site'
        }
        
        # Ajout de Referer pour les domaines canadiens
        if any(domain in url.lower() for domain in ['cbc.ca', 'radio-canada', 'rcavlive']):
            headers['Referer'] = 'https://www.cbc.ca/'
        
        with self.lock:
            if url in self.url_status_cache:
                return self.url_status_cache[url]
        
        # Validation spécialisée pour les flux M3U8/HLS
        if url.endswith('.m3u8') or '/hls/' in url.lower():
            return self._validate_hls_stream(url, headers, timeout, channel_name)
        else:
            return self._validate_regular_url(url, headers, timeout, channel_name)

    def _validate_hls_stream(self, url, headers, timeout, channel_name="Unknown Channel"):
        """Validate HLS/M3U8 streams specifically."""
        try:
            # Pour les flux HLS, nous devons analyser le contenu de la playlist
            response = requests.get(url, headers=headers, timeout=timeout, stream=True)
            
            if response.status_code == 200:
                # Lire les premières lignes pour vérifier que c'est une playlist M3U8 valide
                content = response.text[:2048]  # Premiers 2KB seulement
                
                if '#EXTM3U' in content or '#EXT-X-VERSION' in content:
                    logging.info(f"Channel '{channel_name}': Active HLS stream - URL: {url}")
                    with self.lock:
                        self.url_status_cache[url] = (True, url, "active")
                    return True, url, "active"
                else:
                    logging.warning(f"Channel '{channel_name}': URL returned 200 but invalid M3U8 content - URL: {url}")
                    
            elif response.status_code == 403:
                # Détecter spécifiquement les erreurs 403 comme géo-blocage
                logging.info(f"Channel '{channel_name}': 403 Forbidden - Geo-blocked HLS stream - URL: {url}")
                with self.lock:
                    self.url_status_cache[url] = (True, url, "geo_blocked")
                return True, url, "geo_blocked"
                    
        except requests.RequestException as e:
            logging.debug(f"Channel '{channel_name}': HLS validation failed - URL: {url} - Error: {e}")
        
        # Si la validation HLS échoue, essayer en tant qu'URL normale
        return self._validate_regular_url(url, headers, timeout, channel_name)

    def _validate_regular_url(self, url, headers, timeout, channel_name="Unknown Channel"):
        """Validate regular URLs with standard HTTP methods."""
        try:
            # Essayer HEAD d'abord
            response = requests.head(url, timeout=timeout, headers=headers, allow_redirects=True)
            if response.status_code < 400:
                logging.info(f"Channel '{channel_name}': Active (HEAD) - URL: {url}")
                with self.lock:
                    self.url_status_cache[url] = (True, url, "active")
                return True, url, "active"
            elif response.status_code == 403:
                logging.info(f"Channel '{channel_name}': 403 Forbidden - Geo-blocked (HEAD) - URL: {url}")
                with self.lock:
                    self.url_status_cache[url] = (True, url, "geo_blocked")
                return True, url, "geo_blocked"
        except requests.RequestException:
            pass
        
        try:
            # Essayer GET en streaming
            with requests.get(url, stream=True, timeout=timeout, headers=headers) as r:
                if r.status_code < 400:
                    logging.info(f"Channel '{channel_name}': Active (GET) - URL: {url}")
                    with self.lock:
                        self.url_status_cache[url] = (True, url, "active")
                    return True, url, "active"
                elif r.status_code == 403:
                    logging.info(f"Channel '{channel_name}': 403 Forbidden - Geo-blocked (GET) - URL: {url}")
                    with self.lock:
                        self.url_status_cache[url] = (True, url, "geo_blocked")
                    return True, url, "geo_blocked"
        except requests.RequestException as e:
            logging.debug(f"Channel '{channel_name}': Regular validation failed - URL: {url} - Error: {e}")
        
        # Dernière tentative avec protocole alternatif
        try:
            alt_url = url.replace('http://', 'https://') if url.startswith('http://') else url.replace('https://', 'http://')
            response = requests.head(alt_url, timeout=timeout, headers=headers, allow_redirects=True)
            if response.status_code < 400:
                logging.info(f"Channel '{channel_name}': Active (HEAD, switched protocol) - Original URL: {url} - Working URL: {alt_url}")
                with self.lock:
                    self.url_status_cache[url] = (True, alt_url, "active")
                return True, alt_url, "active"
            elif response.status_code == 403:
                logging.info(f"Channel '{channel_name}': 403 Forbidden - Geo-blocked (HEAD, switched protocol) - Original URL: {url} - Tested URL: {alt_url}")
                with self.lock:
                    self.url_status_cache[url] = (True, alt_url, "geo_blocked")
                return True, alt_url, "geo_blocked"
        except requests.RequestException:
            pass
        
        # Si tout échoue, retourner False
        logging.warning(f"Channel '{channel_name}': All validation methods failed - URL: {url}")
        with self.lock:
            self.url_status_cache[url] = (False, url, "inactive")
        return False, url, "inactive"

    def test_cuisine_detection(self, lines):
        """Test spécialisé pour détecter les lignes Cuisine et Zeste."""
        logging.info("=" * 60)
        logging.info("=== CUISINE & ZESTE DETECTION TEST ===")
        cuisine_lines = []
        zeste_lines = []
        
        for line_num, line in enumerate(lines, 1):
            if 'cuisine' in line.lower():
                cuisine_lines.append(f"Line {line_num}: {line}")
            if 'zeste' in line.lower():
                zeste_lines.append(f"Line {line_num}: {line}")
        
        logging.info(f"CUISINE lines found: {len(cuisine_lines)}")
        for line in cuisine_lines:
            logging.info(f"  {line}")
            
        logging.info(f"ZESTE lines found: {len(zeste_lines)}")
        for line in zeste_lines:
            logging.info(f"  {line}")
            
        logging.info("=== END CUISINE & ZESTE TEST ===")
        logging.info("=" * 60)

    def parse_and_store(self, lines, source_url):
        """Parse M3U lines and store channels with enhanced debugging."""
        current_channel = {}
        channel_count = 0
        excluded_count = 0
        non_http_skipped = 0
        
        # ← NOUVEAU : Compteurs pour diagnostic spécialisé
        total_extinf_lines = 0
        cuisine_extinf_found = 0
        cuisine_urls_processed = 0
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if line.startswith('#EXTINF:'):
                total_extinf_lines += 1
                
                match = re.search(r'tvg-logo="([^"]*)"', line)
                logo = match.group(1) if match and match.group(1) else self.default_logo
                
                match = re.search(r'group-title="([^"]*)"', line)
                group = match.group(1) if match else "Uncategorized"
                
                # ← NOUVEAU : Log spécialisé pour le groupe Cuisine
                if "cuisine" in group.lower():
                    cuisine_extinf_found += 1
                    logging.debug(f"CUISINE FOUND - Line {line_num}: Group='{group}' Line='{line}'")
                
                # Logique d'exclusion améliorée
                excluded = False
                for excluded_item in self.excluded_groups:
                    if group.lower() == excluded_item.lower():
                        excluded = True
                        logging.debug(f"EXCLUDED (exact): Line {line_num}, Group '{group}' matches '{excluded_item}'")
                        break
                    elif re.search(r'\b' + re.escape(excluded_item.lower()) + r'\b', group.lower()):
                        excluded = True
                        logging.debug(f"EXCLUDED (word): Line {line_num}, Group '{group}' contains word '{excluded_item}'")
                        break
                
                if excluded:
                    current_channel = {}
                    excluded_count += 1
                    continue
                
                match = re.search(r',(.+)$', line)
                name = match.group(1).strip() if match else "Unnamed Channel"
                
                # ← NOUVEAU : Log pour toutes les chaînes détectées
                logging.debug(f"Line {line_num}: Channel '{name}' in group '{group}'")
                
                current_channel = {
                    'name': name,
                    'logo': logo,
                    'group': group,
                    'source': source_url,
                    'line_num': line_num  # Pour debug
                }
                
            elif line and not line.startswith('#') and current_channel:
                # ← NOUVEAU : Log détaillé des URLs
                logging.debug(f"Line {line_num}: Processing URL for '{current_channel.get('name', 'Unknown')}': {line}")
                
                if line.startswith(('http://', 'https://')):
                    # ← NOUVEAU : Log spécialisé pour les URLs du groupe Cuisine
                    if current_channel.get('group', '').lower() == 'cuisine':
                        cuisine_urls_processed += 1
                        logging.debug(f"CUISINE URL PROCESSED: '{current_channel['name']}' -> {line}")
                    
                    with self.lock:
                        if line not in self.seen_urls:
                            self.seen_urls.add(line)
                            current_channel['url'] = line
                            self.channels[current_channel['group']].append(current_channel)
                            channel_count += 1
                            
                            # ← NOUVEAU : Log de confirmation d'ajout
                            logging.debug(f"ADDED: '{current_channel['name']}' to group '{current_channel['group']}'")
                        else:
                            logging.debug(f"DUPLICATE URL SKIPPED: {line}")
                    
                    current_channel = {}
                else:
                    non_http_skipped += 1
                    logging.debug(f"SKIPPED non-HTTP: '{current_channel.get('name', 'Unknown')}' -> {line}")
        
        # ← NOUVEAU : Résumé de diagnostic complet
        logging.info(f"PARSING SUMMARY for {source_url}:")
        logging.info(f"  - Total EXTINF lines: {total_extinf_lines}")
        logging.info(f"  - Cuisine EXTINF found: {cuisine_extinf_found}")
        logging.info(f"  - Cuisine URLs processed: {cuisine_urls_processed}")
        logging.info(f"  - Total channels added: {channel_count}")
        logging.info(f"  - Excluded: {excluded_count}")
        logging.info(f"  - Non-HTTP skipped: {non_http_skipped}")
        
        # Diagnostic des groupes finaux
        found_groups = set(ch['group'] for ch_list in self.channels.values() for ch in ch_list)
        logging.info(f"Groups found in this source: {', '.join(sorted(found_groups))}")
        
        # ← NOUVEAU : Vérification spéciale pour Cuisine
        cuisine_channels = [ch for ch_list in self.channels.values() for ch in ch_list if ch['group'].lower() == 'cuisine']
        logging.info(f"CUISINE CHANNELS FINAL COUNT: {len(cuisine_channels)}")
        for ch in cuisine_channels:
            logging.info(f"  - {ch['name']} -> {ch['url']}")

    def filter_active_channels(self):
        """Filter out inactive channels, skippable for speed."""
        if not self.check_links:
            logging.info("Skipping link activity check for speed")
            return
        
        active_channels = defaultdict(list)
        all_channels = [(group, ch) for group, chans in self.channels.items() for ch in chans]
        url_set = set()
        
        logging.info(f"Total channels to check: {len(all_channels)}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_channel = {
                executor.submit(self.check_link_active, ch['url'], ch['name']): (group, ch)
                for group, ch in all_channels if ch['url'] not in url_set and not url_set.add(ch['url'])
            }
            for future in concurrent.futures.as_completed(future_to_channel):
                group, channel = future_to_channel[future]
                try:
                    result = future.result()
                    if result is not None and len(result) >= 2:
                        if len(result) == 3:
                            is_active, updated_url, status_type = result
                        else:
                            is_active, updated_url = result
                            status_type = "active" if is_active else "inactive"
                        
                        if is_active:
                            channel['url'] = updated_url
                            
                            if status_type == "geo_blocked":
                                if not channel['name'].endswith('[Geo-blocked]'):
                                    channel['name'] = f"{channel['name']} [Geo-blocked]"
                                    logging.info(f"Tagged as geo-blocked: {channel['name']} - URL: {channel['url']}")
                            
                            active_channels[group].append(channel)
                        else:
                            logging.warning(f"Channel '{channel['name']}' is inactive - URL: {channel['url']}")
                    else:
                        logging.warning(f"Verification failed for channel '{channel['name']}' - URL: {channel['url']}")
                except Exception as e:
                    logging.error(f"Error checking channel '{channel['name']}' - URL: {channel['url']} - Error: {e}")

        self.channels = active_channels
        
        total_active = sum(len(ch) for ch in active_channels.values())
        geo_blocked_count = sum(1 for channels in active_channels.values() 
                               for channel in channels 
                               if '[Geo-blocked]' in channel['name'])
        
        logging.info(f"Active channels after filtering: {total_active}")
        logging.info(f"Geo-blocked channels detected: {geo_blocked_count}")

    def process_sources(self, source_urls):
        """Process sources sequentially for better control."""
        self.channels.clear()
        self.seen_urls.clear()
        self.url_status_cache.clear()
        
        all_m3u_urls = set()
        for url in source_urls:
            html_content, lines = self.fetch_content(url)
            if url.endswith('.html'):
                m3u_urls = self.extract_stream_urls_from_html(html_content, url)
                all_m3u_urls.update(m3u_urls)
            else:
                # ← NOUVEAU : Test de détection avant parsing
                self.test_cuisine_detection(lines)
                self.parse_and_store(lines, url)
        
        for m3u_url in all_m3u_urls:
            _, lines = self.fetch_content(m3u_url)
            self.test_cuisine_detection(lines)
            self.parse_and_store(lines, m3u_url)
        
        if self.channels:
            self.filter_active_channels()
        else:
            logging.warning("No channels parsed from sources")

    def export_m3u(self, filename="LiveTV.m3u"):
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('#EXTM3U\n')
            for group, channels in self.channels.items():
                for channel in channels:
                    f.write(f'#EXTINF:-1 tvg-logo="{channel["logo"]}" group-title="{group}",{channel["name"]}\n')
                    f.write(f'{channel["url"]}\n')
        logging.info(f"Exported M3U to {filepath}")
        return filepath

    def export_txt(self, filename="LiveTV.txt"):
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            for group, channels in sorted(self.channels.items()):
                f.write(f"Group: {group}\n")
                for channel in channels:
                    f.write(f"Name: {channel['name']}\n")
                    f.write(f"URL: {channel['url']}\n")
                    f.write(f"Logo: {channel['logo']}\n")
                    f.write(f"Source: {channel['source']}\n")
                    f.write("-" * 50 + "\n")
                f.write("\n")
        logging.info(f"Exported TXT to {filepath}")
        return filepath

    def export_json(self, filename="LiveTV.json"):
        filepath = os.path.join(self.output_dir, filename)
        mumbai_tz = pytz.timezone('Asia/Kolkata')
        current_time = datetime.now(mumbai_tz).strftime('%Y-%m-%d %H:%M:%S')
        
        json_data = {
            "date": current_time,
            "channels": dict(self.channels),
            "excluded_groups": self.excluded_groups  # Ajout info sur les groupes exclus
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, ensure_ascii=False, indent=2)
        logging.info(f"Exported JSON to {filepath}")
        return filepath

    def export_custom(self, filename="LiveTV"):
        """Export to custom format without extension."""
        filepath = os.path.join(self.output_dir, filename)
        custom_data = []
        
        for group, channels in self.channels.items():
            for channel in channels:
                custom_data.append({
                    "name": channel['name'],
                    "type": group,
                    "url": channel['url'],
                    "img": channel['logo']
                })
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(custom_data, f, ensure_ascii=False, indent=2)
        logging.info(f"Exported custom format to {filepath}")
        return filepath

    def get_excluded_groups_info(self):
        """Retourne des informations sur les groupes exclus."""
        return {
            "excluded_groups": self.excluded_groups,
            "excluded_count": len(self.excluded_groups)
        }

def main():
    # Détecter la géolocalisation du serveur GitHub Actions
    server_location = get_server_geolocation()
    
    # Liste d'exclusion nettoyée pour éviter faux positifs
    excluded_groups = [
        # Pays - noms complets pour éviter conflits
        "Argentina", "Austria", "Brazil", "Chile", "Denmark", "Germany", 
        "India", "Italy", "Mexico", "Norway", "South Korea", "Spain", 
        "Sweden", "Switzerland", "United Kingdom", "United States",
        # Autres - termes spécifiques
        "Offline", "Test", "Demo", "Shopping", "Teleshopping"
    ]
    
    # Specific M3U sources
    source_urls = [        
        "https://github.com/Sphinxroot/QC-TV/raw/16afc34391cf7a1dbc0b6a8273476a7d3f9ca33b/Quebec.m3u",
        # Autres sources commentées pour test
        # "https://raw.githubusercontent.com/HelmerLuzo/PlutoTV_HL/refs/heads/main/tv/m3u/PlutoTV_tv_CA.m3u",
        # "https://iptv-org.github.io/iptv/countries/ca.m3u",
        # "https://list.iptvcat.com/my_list/33b417553a834a782ea5d4d15abbef92.m3u8",
        # "https://github.com/BuddyChewChew/app-m3u-generator/raw/refs/heads/main/playlists/plutotv_all.m3u",
        # "https://github.com/BuddyChewChew/app-m3u-generator/raw/refs/heads/main/playlists/samsungtvplus_all.m3u",
    ]

    # Instanciation avec liste d'exclusion
    collector = M3UCollector(
        country="Mikhoul", 
        check_links=True, 
        excluded_groups=excluded_groups
    )
    
    # Affichage des groupes exclus
    excluded_info = collector.get_excluded_groups_info()
    logging.info(f"Groupes exclus configurés: {excluded_info['excluded_count']}")
    logging.info(f"Liste d'exclusion: {', '.join(excluded_groups)}")
    
    collector.process_sources(source_urls)
    
    # Export files
    collector.export_m3u("LiveTV.m3u")
    collector.export_txt("LiveTV.txt")
    collector.export_json("LiveTV.json")
    collector.export_custom("LiveTV")
    
    total_channels = sum(len(ch) for ch in collector.channels.values())
    mumbai_time = datetime.now(pytz.timezone('Asia/Kolkata'))
    logging.info(f"[{mumbai_time}] Collected {total_channels} unique channels for Mikhoul")
    logging.info(f"Groups found: {len(collector.channels)}")
    
    # Affichage des groupes finaux
    final_groups = list(collector.channels.keys())
    logging.info(f"Final groups after exclusion: {', '.join(sorted(final_groups))}")
    
    # Affichage final de la géolocalisation pour référence
    if server_location:
        logging.info(f"All tests performed from: {server_location['country']} ({server_location['country_code']})")

if __name__ == "__main__":
    main()
