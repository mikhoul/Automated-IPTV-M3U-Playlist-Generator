import requests
import json
import os
import re
from urllib.parse import urlparse, urljoin, quote
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import pytz
import concurrent.futures
import threading
import logging
import time
import hashlib
import tempfile
import zipfile
from pathlib import Path
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import csv

class ValidationColorFormatter(logging.Formatter):
    """Enhanced logging formatter with underlined very light gray URLs - FIXED VERSION."""
    
    # ANSI escape codes for colors
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    UNDERLINE = "\x1b[4m"  # FIXED: Added underline support
    
    # Color definitions - FIXED: Very light gray and underline for URLs
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"
    MAGENTA = "\x1b[35m"
    CYAN = "\x1b[36m"
    WHITE = "\x1b[37m"
    BRIGHT_RED = "\x1b[91m"
    BRIGHT_GREEN = "\x1b[92m"
    BRIGHT_YELLOW = "\x1b[93m"
    BRIGHT_BLUE = "\x1b[94m"
    BRIGHT_CYAN = "\x1b[96m"
    
    # FIXED: Single red shade and very light gray + underline for URLs
    INACTIVE_RED = "\x1b[38;2;220;20;60m"  # Single consistent red for INACTIVE
    VERY_LIGHT_GRAY = "\x1b[97m"  # FIXED: Very light gray (bright white)
    LIGHT_ORANGE = "\x1b[38;5;214m"  # Consistent light orange for geo-blocking

    # Map log levels to colors
    LEVEL_COLORS = {
        logging.DEBUG: CYAN,
        logging.INFO: BRIGHT_BLUE,
        logging.WARNING: BRIGHT_YELLOW,
        logging.ERROR: BRIGHT_RED,
        logging.CRITICAL: BOLD + BRIGHT_RED
    }

    # FIXED: Single red shade, removed Warning color, improved keyword list
    KEYWORD_COLORS = {
        # Positive status - GREEN ONLY
        'Active HLS stream': BRIGHT_GREEN,
        'Active (HEAD)': BRIGHT_GREEN,
        'Active (GET)': BRIGHT_GREEN,
        'Active': BRIGHT_GREEN,
        'SUCCESS': BRIGHT_GREEN,
        'Success': BRIGHT_GREEN,
        
        # Negative status - SINGLE RED SHADE (FIXED)
        'INACTIVE': BOLD + INACTIVE_RED,
        'inactive': INACTIVE_RED,
        'All validation methods failed': INACTIVE_RED,
        'Failed': INACTIVE_RED,
        'FAILED': BOLD + INACTIVE_RED,
        
        # Error codes - SINGLE RED SHADE (FIXED)
        '[ERROR_400]': BOLD + INACTIVE_RED,
        '[ERROR_404]': BOLD + INACTIVE_RED,
        '[ERROR_500]': BOLD + INACTIVE_RED,
        '[ERROR_502]': BOLD + INACTIVE_RED,
        '[ERROR_503]': BOLD + INACTIVE_RED,
        '[CONNECTION_FAILED]': BOLD + INACTIVE_RED,
        
        # Geo-blocking - CONSISTENT LIGHT ORANGE
        'Geo-blocked HLS stream': LIGHT_ORANGE,
        'Geo-blocked (HEAD)': LIGHT_ORANGE,
        'Geo-blocked (GET)': LIGHT_ORANGE,
        'Geo-blocked': LIGHT_ORANGE,
        '[Geo-blocked]': LIGHT_ORANGE,
        'Tagged as geo-blocked': LIGHT_ORANGE,
        'geo_blocked': LIGHT_ORANGE,
        '403 Forbidden': LIGHT_ORANGE,
        
        # Channel processing
        'CUISINE': BOLD + MAGENTA,
        'Cuisine': MAGENTA,
        
        # Validation progress
        'Validation progress': BLUE,
        'Starting comprehensive link validation': BOLD + BLUE,
        'Link validation complete': BOLD + GREEN,
        
        # HTTP status codes - SINGLE RED SHADE (FIXED)
        'Bad Request': INACTIVE_RED,
        'Internal Server Error': INACTIVE_RED,
        'Bad Gateway': INACTIVE_RED,
        'Service Unavailable': INACTIVE_RED,
        
        # Processing stages
        'PHASE 1 COMPLETE': BOLD + GREEN,
        'Processing complete': BOLD + GREEN,
        'Deduplication complete': GREEN,
        'Starting post-processing': BLUE,
    }

    def __init__(self, fmt=None, datefmt=None):
        if fmt is None:
            fmt = '%(asctime)s - %(levelname)s - %(message)s'
        super().__init__(fmt, datefmt)

    def format(self, record):
        # Color the levelname
        level_color = self.LEVEL_COLORS.get(record.levelno, self.RESET)
        original_levelname = record.levelname
        record.levelname = f"{level_color}{record.levelname}{self.RESET}"

        # Get the formatted message
        message = super().format(record)
        
        # Restore original levelname
        record.levelname = original_levelname

        # FIXED: Color ALL URLs with underline + very light gray using lambda
        url_pattern = r'(https?://[^\s]+)'
        message = re.sub(url_pattern, 
                        lambda m: f'{self.UNDERLINE}{self.VERY_LIGHT_GRAY}{m.group(1)}{self.RESET}', 
                        message)

        # Color keywords with proper order (longer phrases first to prevent conflicts)
        sorted_keywords = sorted(self.KEYWORD_COLORS.items(), key=lambda x: len(x[0]), reverse=True)
        for keyword, color_code in sorted_keywords:
            if keyword in message:
                colored_keyword = f"{color_code}{keyword}{self.RESET}"
                message = message.replace(keyword, colored_keyword)
        
        return message

def setup_colored_logging():
    """Setup colored logging with underlined very light gray URLs."""
    formatter = ValidationColorFormatter()
    logger = logging.getLogger()
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create console handler with colored formatting
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(console_handler)
    logger.setLevel(logging.INFO)
    
    return logger

# Configure colored logging with URL underline fix
setup_colored_logging()

def get_server_geolocation():
    """
    Retrieve server geolocation information for logging and analytics.
    Returns a dictionary with location data or None if failed.
    """
    try:
        # Get public IP address
        ip_response = requests.get('https://api.ipify.org?format=json', timeout=10)
        server_ip = ip_response.json()['ip']
        
        # Get geolocation data
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

def calculate_file_hash(content):
    """Calculate MD5 hash of content for change detection."""
    return hashlib.md5(content.encode('utf-8')).hexdigest()

def sanitize_filename(filename):
    """Sanitize filename for safe file system operations."""
    return re.sub(r'[<>:"/\\|?*]', '_', filename)

def format_duration(seconds):
    """Format duration in human readable format."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds//60}m {seconds%60}s"
    else:
        return f"{seconds//3600}h {(seconds%3600)//60}m"

class M3UCollector:
    """
    Comprehensive M3U playlist collector and processor.
    Handles channel extraction, validation, filtering, and export in multiple formats.
    """
    
    def __init__(self, country="Mikhoul", base_dir="LiveTV", check_links=False, excluded_groups=None, config=None):
        """
        Initialize the M3U collector with comprehensive configuration options.
        
        Args:
            country (str): Country identifier for output organization
            base_dir (str): Base directory for output files
            check_links (bool): Enable link validation checking
            excluded_groups (list): List of group names to exclude
            config (dict): Additional configuration parameters
        """
        # Core configuration
        self.country = country
        self.base_dir = base_dir
        self.check_links = check_links
        self.excluded_groups = excluded_groups or []
        self.config = config or {}
        
        # Data storage
        self.channels = defaultdict(list)
        self.seen_urls = set()
        self.url_status_cache = {}
        self.duplicate_channels = []
        self.failed_urls = []
        self.statistics = defaultdict(int)
        
        # Configuration parameters
        self.default_logo = self.config.get('default_logo', "https://buddytv.netlify.app/img/no-logo.png")
        self.user_agent = self.config.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        self.max_workers = self.config.get('max_workers', 10)
        self.request_timeout = self.config.get('request_timeout', 10)
        self.max_retries = self.config.get('max_retries', 3)
        self.retry_delay = self.config.get('retry_delay', 1)
        
        # Output and processing
        self.output_dir = os.path.join(base_dir, country)
        self.temp_dir = os.path.join(self.output_dir, 'temp')
        self.cache_dir = os.path.join(self.output_dir, 'cache')
        self.lock = threading.Lock()
        self.skipped_non_http_count = 0
        
        # Quality and filtering
        self.quality_preferences = self.config.get('quality_preferences', ['1080p', '720p', '480p', '360p'])
        self.language_preferences = self.config.get('language_preferences', ['en', 'fr'])
        self.enable_deduplication = self.config.get('enable_deduplication', True)
        self.enable_quality_sorting = self.config.get('enable_quality_sorting', True)
        
        # Create necessary directories
        for directory in [self.output_dir, self.temp_dir, self.cache_dir]:
            os.makedirs(directory, exist_ok=True)
        
        # Initialize counters
        self.start_time = time.time()
        self.channels_processed = 0
        self.urls_validated = 0

    def fetch_content(self, url):
        """
        Fetch content from URL with retry mechanism and comprehensive error handling.
        
        Args:
            url (str): URL to fetch
            
        Returns:
            tuple: (content_string, lines_list)
        """
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        try:
            with requests.get(url, stream=True, headers=headers, timeout=10) as response:
                response.raise_for_status()
                lines = [line.decode('utf-8', errors='replace') if isinstance(line, bytes) else line 
                        for line in response.iter_lines()]
                return '\n'.join(lines), lines
        except requests.RequestException as e:
            logging.warning(f"Failed to fetch {url}: {str(e)}")
            return None, []

    def extract_stream_urls_from_html(self, html_content, base_url):
        """
        Extract streaming URLs from HTML content using advanced parsing techniques.
        
        Args:
            html_content (str): HTML content to parse
            base_url (str): Base URL for resolving relative links
            
        Returns:
            list: Extracted streaming URLs
        """
        if not html_content:
            return []
            
        soup = BeautifulSoup(html_content, 'html.parser')
        stream_urls = set()
        
        # Extract from various HTML elements
        for link in soup.find_all('a', href=True):
            href = link['href']
            parsed_base = urlparse(base_url)
            parsed_href = urlparse(href)
            
            if not parsed_href.scheme:
                href = f"{parsed_base.scheme}://{parsed_base.netloc}{href}"
            
            if (href.endswith(('.m3u', '.m3u8')) or 
                re.match(r'https?://.*\.(ts|mp4|avi|mkv|flv|wmv)', href) or
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
        
        # Add domain-specific headers
        if any(domain in url.lower() for domain in ['cbc.ca', 'radio-canada', 'rcavlive']):
            headers['Referer'] = 'https://www.cbc.ca'
        
        # Check cache first
        with self.lock:
            if url in self.url_status_cache:
                return self.url_status_cache[url]
        
        # Use specialized validation based on URL type
        if url.endswith('.m3u8') or 'hls' in url.lower():
            return self.validate_hls_stream(url, headers, timeout, channel_name)
        else:
            return self.validate_regular_url(url, headers, timeout, channel_name)

    def validate_hls_stream(self, url, headers, timeout, channel_name="Unknown Channel"):
        """Validate HLS/M3U8 streams specifically."""
        try:
            response = requests.get(url, headers=headers, timeout=timeout, stream=True)
            if response.status_code == 200:
                content = response.text[:2048]
                if '#EXTM3U' in content or '#EXT-X-VERSION' in content:
                    logging.info(f"Channel '{channel_name}': Active HLS stream - URL: {url}")
                    with self.lock:
                        self.url_status_cache[url] = (True, url, 'active')
                    return True, url, 'active'
            elif response.status_code == 403:
                logging.info(f"Channel '{channel_name}': 403 Forbidden - Geo-blocked HLS stream - URL: {url}")
                with self.lock:
                    self.url_status_cache[url] = (True, url, 'geo_blocked')
                return True, url, 'geo_blocked'
        except requests.RequestException as e:
            logging.debug(f"Channel '{channel_name}': HLS validation failed - URL: {url} - Error: {e}")
        
        return self.validate_regular_url(url, headers, timeout, channel_name)

    def validate_regular_url(self, url, headers, timeout, channel_name="Unknown Channel"):
        """Validate regular URLs with standard HTTP methods."""
        try:
            response = requests.head(url, timeout=timeout, headers=headers, allow_redirects=True)
            if response.status_code < 400:
                logging.info(f"Channel '{channel_name}': Active (HEAD) - URL: {url}")
                with self.lock:
                    self.url_status_cache[url] = (True, url, 'active')
                return True, url, 'active'
            elif response.status_code == 403:
                logging.info(f"Channel '{channel_name}': 403 Forbidden - Geo-blocked (HEAD) - URL: {url}")
                with self.lock:
                    self.url_status_cache[url] = (True, url, 'geo_blocked')
                return True, url, 'geo_blocked'
        except requests.RequestException:
            pass
        
        try:
            with requests.get(url, stream=True, timeout=timeout, headers=headers) as r:
                if r.status_code < 400:
                    logging.info(f"Channel '{channel_name}': Active (GET) - URL: {url}")
                    with self.lock:
                        self.url_status_cache[url] = (True, url, 'active')
                    return True, url, 'active'
                elif r.status_code == 403:
                    logging.info(f"Channel '{channel_name}': 403 Forbidden - Geo-blocked (GET) - URL: {url}")
                    with self.lock:
                        self.url_status_cache[url] = (True, url, 'geo_blocked')
                    return True, url, 'geo_blocked'
        except requests.RequestException as e:
            logging.debug(f"Channel '{channel_name}': Regular validation failed - URL: {url} - Error: {e}")
        
        logging.warning(f"Channel '{channel_name}': All validation methods failed - URL: {url}")
        with self.lock:
            self.url_status_cache[url] = (False, url, 'inactive')
        return False, url, 'inactive'

    def test_cuisine_detection(self, lines):
        """
        Detect and count specific content types in the playlist for analytics.
        
        Args:
            lines (list): Lines from the playlist
        """
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
        """
        Parse M3U playlist content and store channel information with comprehensive processing.
        
        Args:
            lines (list): Playlist lines to parse
            source_url (str): Source URL for reference
        """
        current_channel = {}
        channel_count = 0
        total_extinf_lines = 0
        group_occurrences = defaultdict(int)
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Log specific lines for debugging
            if line_num in [537, 539, 541] and 'group-title' in line:
                logging.info(f"RAW GROUP DETECTED Line {line_num}: {line}")
            
            if line_num % 100 == 0 or line_num in [1, 537, 538, 539, 540, 541, 542]:
                logging.info(f"Parsing line {line_num}/{len(lines)}: {line[:60]}")
            
            if line.startswith('#EXTINF'):
                total_extinf_lines += 1
                
                # Extract logo
                try:
                    match = re.search(r'tvg-logo="([^"]*)"', line)
                    logo = match.group(1) if match and match.group(1) else self.default_logo
                except Exception:
                    logo = self.default_logo
                
                # Extract group
                try:
                    match = re.search(r'group-title="([^"]*)"', line)
                    if match:
                        group = match.group(1).strip()
                        
                        # Handle encoding issues
                        try:
                            group = group.encode('latin-1').decode('utf-8')
                        except:
                            pass  # Keep original if conversion fails
                        
                        # Normalize specific group names
                        if group.lower() == 'cuisine':
                            group = 'Cuisine'
                        
                        if not group or group.isspace():
                            group = "Uncategorized"
                    else:
                        group = "Uncategorized"
                except Exception as e:
                    logging.error(f"Line {line_num}: GROUP EXTRACTION ERROR: {e}")
                    group = "Uncategorized"
                
                # Special logging for Cuisine
                if 'cuisine' in group.lower():
                    logging.info(f"CUISINE GROUP CONFIRMED: {group} at line {line_num}")
                
                group_occurrences[group] += 1
                
                # Check exclusion rules
                excluded = any(
                    group.lower() == excl.lower() or 
                    re.search(r'\b' + re.escape(excl.lower()) + r'\b', group.lower())
                    for excl in self.excluded_groups
                )
                if excluded:
                    current_channel = {}
                    continue
                
                # Extract channel name
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
                        
                        # Special logging for Cuisine channels
                        if current_channel['group'].lower() == 'cuisine':
                            logging.info(f"CUISINE CHANNEL ADDED: {current_channel['name']} to group {current_channel['group']}")
                        
                current_channel = {}
        
        # Log parsing results
        logging.info(f"GROUP OCCURRENCES SUMMARY:")
        for group, count in group_occurrences.items():
            logging.info(f"  - {group}: {count} channels")
        
        logging.info(f"Parsing complete: {channel_count} channels added from {source_url}")

    def filter_active_channels(self):
        """
        Filter channels by checking URL availability with detailed validation logging.
        Uses concurrent processing for performance optimization.
        """
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
                for group, ch in all_channels
                if ch['url'] not in url_set and not url_set.add(ch['url'])
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
                    logging.error(f"Error checking channel {channel['name']} - URL: {channel['url']} - Error: {e}")
        
        self.channels = active_channels
        logging.info(f"Active channels after filtering: {sum(len(ch) for ch in active_channels.values())}")

    def process_sources(self, source_urls):
        """
        Process all source URLs with comprehensive pipeline.
        
        Args:
            source_urls (list): List of source URLs to process
        """
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
        
        # Process extracted M3U URLs
        for m3u_url in all_m3u_urls:
            _, lines = self.fetch_content(m3u_url)
            self.test_cuisine_detection(lines)
            self.parse_and_store(lines, m3u_url)
        
        total_parsed = sum(len(ch) for ch in self.channels.values())
        logging.info(f"PHASE 1 COMPLETE: {total_parsed} channels parsed, groups: {', '.join(sorted(self.channels.keys()))}")
        
        # Special reporting for Cuisine channels
        cuisine_channels = [ch for ch_list in self.channels.values() for ch in ch_list if ch['group'].lower() == 'cuisine']
        logging.info(f"CUISINE channels after parsing: {len(cuisine_channels)}")
        
        if cuisine_channels:
            logging.info(f"CUISINE CHANNELS FOUND:")
            for ch in cuisine_channels:
                logging.info(f"  - {ch['name']} - {ch['url']}")
        
        if self.channels and self.check_links:
            self.filter_active_channels()

    def export_m3u(self, filename="LiveTV.m3u"):
        """Export channels to standard M3U playlist format."""
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
        """Export channels to human-readable text format."""
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
        """Export channels to JSON format."""
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
        """Export channels to custom format."""
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
        """Get information about excluded groups configuration."""
        return {
            'excluded_groups': self.excluded_groups,
            'excluded_count': len(self.excluded_groups)
        }

def main():
    """Main execution function with comprehensive configuration and FIXED URL coloring."""
    # Test URL coloring immediately
    logging.info("Testing URL colors: https://example.com/test.m3u8 and https://test.com/stream.m3u8")
    
    server_location = get_server_geolocation()
    
    excluded_groups = [
        "Argentina", "Austria", "Brazil", "Chile", "Denmark", "Germany", 
        "India", "Italy", "Mexico", "Norway", "South Korea", "Spain", 
        "Sweden", "Switzerland", "United Kingdom", "United States",
        "Offline", "Test", "Demo", "Shopping", "Teleshopping"
    ]
    
    source_urls = [
        "https://github.com/Sphinxroot/QC-TV/raw/16afc34391cf7a1dbc0b6a8273476a7d3f9ca33b/Quebec.m3u"
    ]
    
    collector = M3UCollector(
        country="Mikhoul", 
        check_links=False, 
        excluded_groups=excluded_groups
    )
    
    excluded_info = collector.get_excluded_groups_info()
    logging.info(f"Groupes exclus: {excluded_info['excluded_count']} | {', '.join(excluded_groups[:5])}...")
    
    collector.process_sources(source_urls)
    
    # Export to all formats
    collector.export_m3u("LiveTV.m3u")
    collector.export_txt("LiveTV.txt")
    collector.export_json("LiveTV.json")
    collector.export_custom("LiveTV")
    
    total_channels = sum(len(ch) for ch in collector.channels.values())
    mumbai_time = datetime.now(pytz.timezone('Asia/Kolkata'))
    
    logging.info(f"{mumbai_time}: Collected {total_channels} unique channels for Mikhoul")
    logging.info(f"Groups found: {len(collector.channels)}")
    
    final_groups = list(collector.channels.keys())
    logging.info(f"Final groups after exclusion: {', '.join(sorted(final_groups))}")
    
    if server_location:
        logging.info(f"All tests performed from: {server_location['country']} ({server_location['country_code']})")

if __name__ == "__main__":
    main()
