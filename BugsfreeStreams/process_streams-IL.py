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

# Logging plus léger : niveau INFO
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_server_geolocation():
    try:
        ip_response = requests.get('https://api.ipify.org?format=json', timeout=10)
        server_ip = ip_response.json()['ip']
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
        logging.info(f"SERVER GEOLOCATION: {location_info['city']}, {location_info['region']}, {location_info['country']} ({location_info['country_code']}) | IP: {location_info['ip']} | Org: {location_info['org']} | TZ: {location_info['timezone']}")
        return location_info
    except Exception as e:
        logging.warning(f"Failed to get server geolocation: {e}")
        return None

class M3UCollector:
    def __init__(self, country="Mikhoul", base_dir="LiveTV", check_links=False, excluded_groups=None):
        self.channels = defaultdict(list)
        self.default_logo = "https://buddytv.netlify.app/img/no-logo.png"
        self.seen_urls = set()
        self.url_status_cache = {}
        self.output_dir = os.path.join(base_dir, country)
        self.lock = threading.Lock()
        self.check_links = check_links
        self.excluded_groups = excluded_groups or []
        self.skipped_non_http_count = 0
        os.makedirs(self.output_dir, exist_ok=True)

    def fetch_content(self, url):
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        try:
            with requests.get(url, stream=True, headers=headers, timeout=10) as response:
                response.raise_for_status()
                lines = [line.decode('utf-8', errors='replace') if isinstance(line, bytes) else line for line in response.iter_lines()]
                return '\n'.join(lines), lines
        except requests.RequestException as e:
            logging.warning(f"Failed to fetch {url}: {str(e)}")
            return None, []

    def extract_stream_urls_from_html(self, html_content, base_url):
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
        return list(stream_urls)

    def check_link_active(self, url, channel_name="Unknown Channel", timeout=9):
        """Check if a link is active, with specialized HLS validation."""
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
        
        if any(domain in url.lower() for domain in ['cbc.ca', 'radio-canada', 'rcavlive']):
            headers['Referer'] = 'https://www.cbc.ca/'
        
        with self.lock:
            if url in self.url_status_cache:
                return self.url_status_cache[url]
        
        if url.endswith('.m3u8') or '/hls/' in url.lower():
            return self._validate_hls_stream(url, headers, timeout, channel_name)
        else:
            return self._validate_regular_url(url, headers, timeout, channel_name)

    def _validate_hls_stream(self, url, headers, timeout, channel_name="Unknown Channel"):
        """Validate HLS/M3U8 streams specifically."""
        try:
            response = requests.get(url, headers=headers, timeout=timeout, stream=True)
            if response.status_code == 200:
                content = response.text[:2048]
                if '#EXTM3U' in content or '#EXT-X-VERSION' in content:
                    logging.info(f"Channel '{channel_name}': Active HLS stream - URL: {url}")
                    with self.lock:
                        self.url_status_cache[url] = (True, url, "active")
                    return True, url, "active"
            elif response.status_code == 403:
                logging.info(f"Channel '{channel_name}': 403 Forbidden - Geo-blocked HLS stream - URL: {url}")
                with self.lock:
                    self.url_status_cache[url] = (True, url, "geo_blocked")
                return True, url, "geo_blocked"
        except requests.RequestException as e:
            logging.debug(f"Channel '{channel_name}': HLS validation failed - URL: {url} - Error: {e}")
        return self._validate_regular_url(url, headers, timeout, channel_name)

    def _validate_regular_url(self, url, headers, timeout, channel_name="Unknown Channel"):
        """Validate regular URLs with standard HTTP methods."""
        try:
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
        
        logging.warning(f"Channel '{channel_name}': All validation methods failed - URL: {url}")
        with self.lock:
            self.url_status_cache[url] = (False, url, "inactive")
        return False, url, "inactive"

    def test_cuisine_detection(self, lines):
        cuisine_lines = []
        zeste_lines = []
        for line_num, line in enumerate(lines, 1):
            if 'cuisine' in line.lower():
                cuisine_lines.append(f"Line {line_num}: {line}")
            if 'zeste' in line.lower():
                zeste_lines.append(f"Line {line_num}: {line}")
        if cuisine_lines or zeste_lines:
            logging.info(f"CUISINE lines found: {len(cuisine_lines)} | ZESTE lines found: {len(zeste_lines)}")

    def parse_and_store(self, lines, source_url):
        current_channel = {}
        channel_count = 0
        total_extinf_lines = 0
        group_occurrences = defaultdict(int)
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Log des lignes critiques pour diagnostic
            if line_num in (537, 539, 541) and "group-title" in line:
                logging.info(f"RAW GROUP DETECTED Line {line_num}: '{line}'")
            
            if line_num % 100 == 0 or line_num in (1, 537, 538, 539, 540, 541, 542):
                logging.info(f"Parsing line {line_num}/{len(lines)}: {line[:60]}")
            
            if line.startswith('#EXTINF:'):
                total_extinf_lines += 1
                try:
                    match = re.search(r'tvg-logo="([^"]*)"', line)
                    logo = match.group(1) if match and match.group(1) else self.default_logo
                except Exception:
                    logo = self.default_logo
                
                # ← CORRECTION DIRECTE : Extraction robuste du groupe
                try:
                    match = re.search(r'group-title="([^"]*)"', line)
                    if match:
                        group = match.group(1).strip()
                        
                        # ← CORRECTION : Normalisation d'encodage seulement si nécessaire
                        try:
                            # Essayer de corriger l'encodage Latin-1 vers UTF-8
                            group = group.encode('latin1').decode('utf-8')
                        except:
                            # Fallback pour les cas déjà corrects
                            pass
                        
                        # ← CORRECTION : Force la valeur correcte pour "Cuisine"
                        if group.lower() == 'cuisine':
                            group = 'Cuisine'
                        
                        # ← CORRECTION : Éviter les groupes vides
                        if not group or group.isspace():
                            group = "Uncategorized"
                    else:
                        group = "Uncategorized"
                except Exception as e:
                    logging.error(f"Line {line_num}: GROUP EXTRACTION ERROR: {e}")
                    group = "Uncategorized"
                
                # ← CORRECTION : Log spécial pour Cuisine
                if "cuisine" in group.lower():
                    logging.info(f"★★★ CUISINE GROUP CONFIRMED: '{group}' at line {line_num}")
                
                # Enregistrement du groupe
                group_occurrences[group] += 1
                
                excluded = any(
                    group.lower() == excl.lower() or re.search(r'\b' + re.escape(excl.lower()) + r'\b', group.lower())
                    for excl in self.excluded_groups
                )
                if excluded:
                    current_channel = {}
                    continue
                try:
                    match = re.search(r',(.+)$', line)
                    name = match.group(1).strip() if match else "Unnamed Channel"
                except Exception:
                    name = "Unnamed Channel"
                current_channel = {
                    'name': name,
                    'logo': logo,
                    'group': group,
                    'source': source_url,
                    'line_num': line_num
                }
            elif line and not line.startswith('#') and current_channel:
                if line.startswith(('http://', 'https://')):
                    if line not in self.seen_urls:
                        self.seen_urls.add(line)
                        current_channel['url'] = line
                        self.channels[current_channel['group']].append(current_channel)
                        channel_count += 1
                        
                        # ← CORRECTION : Log spécial pour les chaînes Cuisine ajoutées
                        if current_channel['group'].lower() == 'cuisine':
                            logging.info(f"★★★ CUISINE CHANNEL ADDED: '{current_channel['name']}' to group '{current_channel['group']}'")
                    current_channel = {}
        
        # Diagnostic des groupes
        logging.info(f"GROUP OCCURRENCES SUMMARY:")
        for group, count in group_occurrences.items():
            logging.info(f"  - {group}: {count} channels")
        
        logging.info(f"Parsing complete: {channel_count} channels added from {source_url}")

    def filter_active_channels(self):
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
                        is_active, updated_url = result[:2]
                        if is_active:
                            channel['url'] = updated_url
                            active_channels[group].append(channel)
                except Exception as e:
                    logging.error(f"Error checking channel '{channel['name']}' - URL: {channel['url']} - Error: {e}")
        self.channels = active_channels
        logging.info(f"Active channels after filtering: {sum(len(ch) for ch in active_channels.values())}")

    def process_sources(self, source_urls):
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
                self.test_cuisine_detection(lines)
                self.parse_and_store(lines, url)
        for m3u_url in all_m3u_urls:
            _, lines = self.fetch_content(m3u_url)
            self.test_cuisine_detection(lines)
            self.parse_and_store(lines, m3u_url)
        total_parsed = sum(len(ch) for ch in self.channels.values())
        logging.info(f"PHASE 1 COMPLETE: {total_parsed} channels parsed, groups: {', '.join(sorted(self.channels.keys()))}")
        cuisine_channels = [ch for ch_list in self.channels.values() for ch in ch_list if ch['group'].lower() == 'cuisine']
        logging.info(f"CUISINE channels after parsing: {len(cuisine_channels)}")
        
        # ← CORRECTION : Affichage détaillé des chaînes Cuisine
        if cuisine_channels:
            logging.info(f"★★★ CUISINE CHANNELS FOUND:")
            for ch in cuisine_channels:
                logging.info(f"★★★   - {ch['name']} -> {ch['url']}")
        
        if self.channels and self.check_links:
            self.filter_active_channels()

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
            "excluded_groups": self.excluded_groups
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, ensure_ascii=False, indent=2)
        logging.info(f"Exported JSON to {filepath}")
        return filepath

    def export_custom(self, filename="LiveTV"):
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
        return {
            "excluded_groups": self.excluded_groups,
            "excluded_count": len(self.excluded_groups)
        }

def main():
    server_location = get_server_geolocation()
    excluded_groups = [
        "Argentina", "Austria", "Brazil", "Chile", "Denmark", "Germany", 
        "India", "Italy", "Mexico", "Norway", "South Korea", "Spain", 
        "Sweden", "Switzerland", "United Kingdom", "United States",
        "Offline", "Test", "Demo", "Shopping", "Teleshopping"
    ]
    source_urls = [
        "https://github.com/Sphinxroot/QC-TV/raw/16afc34391cf7a1dbc0b6a8273476a7d3f9ca33b/Quebec.m3u",
    ]
    collector = M3UCollector(
        country="Mikhoul", 
        check_links=False,
        excluded_groups=excluded_groups
    )
    excluded_info = collector.get_excluded_groups_info()
    logging.info(f"Groupes exclus: {excluded_info['excluded_count']} | {', '.join(excluded_groups)}")
    collector.process_sources(source_urls)
    collector.export_m3u("LiveTV.m3u")
    collector.export_txt("LiveTV.txt")
    collector.export_json("LiveTV.json")
    collector.export_custom("LiveTV")
    total_channels = sum(len(ch) for ch in collector.channels.values())
    mumbai_time = datetime.now(pytz.timezone('Asia/Kolkata'))
    logging.info(f"[{mumbai_time}] Collected {total_channels} unique channels for Mikhoul")
    logging.info(f"Groups found: {len(collector.channels)}")
    final_groups = list(collector.channels.keys())
    logging.info(f"Final groups after exclusion: {', '.join(sorted(final_groups))}")
    if server_location:
        logging.info(f"All tests performed from: {server_location['country']} ({server_location['country_code']})")

if __name__ == "__main__":
    main()
