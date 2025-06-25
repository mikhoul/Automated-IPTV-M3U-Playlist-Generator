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

# Configure logging for production use
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
    
    def __init__(self, country="Mikhoul", base_dir="LiveTV", check_links=True, excluded_groups=None, config=None):
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

    def get_request_headers(self, url=None, custom_headers=None):
        """
        Generate appropriate request headers for different domains and content types.
        
        Args:
            url (str): Target URL for header customization
            custom_headers (dict): Additional custom headers
            
        Returns:
            dict: Configured headers dictionary
        """
        headers = {
            'User-Agent': self.user_agent,
            'Accept': 'application/vnd.apple.mpegurl, application/x-mpegURL, application/octet-stream, */*',
            'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'cross-site',
            'Cache-Control': 'no-cache'
        }
        
        # Add domain-specific headers
        if url:
            domain = urlparse(url).netloc.lower()
            
            if any(d in domain for d in ['cbc.ca', 'radio-canada', 'rcavlive']):
                headers['Referer'] = 'https://www.cbc.ca'
            elif 'tva' in domain:
                headers['Referer'] = 'https://www.tva.ca'
            elif 'telequebec' in domain:
                headers['Referer'] = 'https://www.telequebec.tv'
            elif 'noovo' in domain:
                headers['Referer'] = 'https://www.noovo.ca'
        
        # Merge custom headers
        if custom_headers:
            headers.update(custom_headers)
            
        return headers

    def fetch_content_with_retry(self, url, max_retries=None):
        """
        Fetch content from URL with retry mechanism and comprehensive error handling.
        
        Args:
            url (str): URL to fetch
            max_retries (int): Maximum retry attempts
            
        Returns:
            tuple: (content_string, lines_list, metadata_dict)
        """
        max_retries = max_retries or self.max_retries
        headers = self.get_request_headers(url)
        
        for attempt in range(max_retries + 1):
            try:
                with requests.get(url, stream=True, headers=headers, 
                                timeout=self.request_timeout, allow_redirects=True) as response:
                    response.raise_for_status()
                    
                    # Get content with proper encoding detection
                    content = response.text
                    lines = content.splitlines()
                    
                    # Extract metadata
                    metadata = {
                        'url': response.url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('content-type', ''),
                        'content_length': len(content),
                        'encoding': response.encoding,
                        'final_url': response.url if response.url != url else None
                    }
                    
                    logging.info(f"Successfully fetched {len(lines)} lines from {url}")
                    return content, lines, metadata
                    
            except requests.RequestException as e:
                if attempt < max_retries:
                    wait_time = self.retry_delay * (2 ** attempt)  # Exponential backoff
                    logging.warning(f"Attempt {attempt + 1} failed for {url}: {e}. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    logging.error(f"Failed to fetch {url} after {max_retries + 1} attempts: {e}")
                    self.failed_urls.append({'url': url, 'error': str(e)})
                    
        return None, [], {}

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
            
        stream_urls = set()
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract from various HTML elements
            selectors = [
                'a[href*=".m3u"]', 'a[href*=".m3u8"]',
                'a[href*="playlist"]', 'a[href*="stream"]',
                'source[src*=".m3u8"]', 'video source',
                '[data-url*=".m3u8"]', '[data-stream*="http"]'
            ]
            
            for selector in selectors:
                elements = soup.select(selector)
                for element in elements:
                    href = element.get('href') or element.get('src') or element.get('data-url') or element.get('data-stream')
                    if href:
                        # Resolve relative URLs
                        if not href.startswith(('http://', 'https://')):
                            href = urljoin(base_url, href)
                        
                        # Validate URL format
                        if self.is_valid_stream_url(href):
                            stream_urls.add(href)
            
            # Extract from JavaScript variables and embedded data
            script_tags = soup.find_all('script')
            for script in script_tags:
                if script.string:
                    # Look for stream URLs in JavaScript
                    js_urls = re.findall(r'["\']https?://[^"\']*\.m3u8?[^"\']*["\']', script.string)
                    for js_url in js_urls:
                        clean_url = js_url.strip('\'"')
                        if self.is_valid_stream_url(clean_url):
                            stream_urls.add(clean_url)
            
        except Exception as e:
            logging.warning(f"Error parsing HTML content: {e}")
            
        logging.info(f"Extracted {len(stream_urls)} stream URLs from HTML content")
        return list(stream_urls)

    def is_valid_stream_url(self, url):
        """
        Validate if URL appears to be a streaming URL.
        
        Args:
            url (str): URL to validate
            
        Returns:
            bool: True if URL appears to be a streaming URL
        """
        if not url or not isinstance(url, str):
            return False
            
        # Check for valid protocol
        if not url.startswith(('http://', 'https://')):
            return False
            
        # Check for streaming file extensions and patterns
        streaming_patterns = [
            r'\.m3u8?(\?|$)', r'\.ts(\?|$)', r'\.mp4(\?|$)',
            r'playlist', r'stream', r'live', r'hls',
            r'/master\.', r'/index\.'
        ]
        
        url_lower = url.lower()
        if any(re.search(pattern, url_lower) for pattern in streaming_patterns):
            return True
            
        # Exclude common non-streaming URLs
        exclude_patterns = [
            'github.com', 'gitlab.com', 'bitbucket.com',
            '.html', '.php', '.asp', '.jsp',
            'login', 'signup', 'register', 'admin',
            'telegram', 'discord', 'facebook'
        ]
        
        return not any(pattern in url_lower for pattern in exclude_patterns)

    def check_link_active(self, url, channel_name="Unknown Channel", timeout=None):
        """
        Comprehensive link validation with detailed logging and caching.
        
        Args:
            url (str): URL to check
            channel_name (str): Channel name for detailed logging
            timeout (int): Request timeout
            
        Returns:
            tuple: (is_active, final_url, status_info)
        """
        timeout = timeout or self.request_timeout
        
        # Check cache first
        with self.lock:
            if url in self.url_status_cache:
                cached_result = self.url_status_cache[url]
                # Check if cache is still valid (e.g., 1 hour)
                if time.time() - cached_result.get('timestamp', 0) < 3600:
                    return cached_result['is_active'], cached_result['url'], cached_result['status']
        
        headers = self.get_request_headers(url)
        
        # Use specialized validation based on URL type
        if url.endswith('.m3u8') or 'hls' in url.lower():
            result = self.validate_hls_stream(url, headers, timeout, channel_name)
        else:
            result = self.validate_regular_url(url, headers, timeout, channel_name)
        
        # Cache the result with timestamp
        with self.lock:
            self.url_status_cache[url] = {
                'is_active': result[0],
                'url': result[1],
                'status': result[2],
                'timestamp': time.time()
            }
            
        return result

    def validate_hls_stream(self, url, headers, timeout, channel_name="Unknown Channel"):
        """
        Validate HLS/M3U8 streams with detailed status logging.
        
        Args:
            url (str): URL to validate
            headers (dict): Request headers
            timeout (int): Request timeout
            channel_name (str): Channel name for detailed logging
            
        Returns:
            tuple: (is_active, final_url, status_info)
        """
        try:
            response = requests.get(url, headers=headers, timeout=timeout, stream=True)
            if response.status_code == 200:
                # Check if content looks like a valid M3U8 playlist
                content = response.text[:2048]
                if '#EXTM3U' in content or '#EXT-X-VERSION' in content:
                    logging.info(f"Channel '{channel_name}': Active HLS stream - URL: {url}")
                    return True, url, 'active'
                else:
                    logging.warning(f"Channel '{channel_name}': URL returned 200 but invalid M3U8 content - URL: {url}")
                    return False, url, 'invalid_content'
            elif response.status_code == 403:
                logging.info(f"Channel '{channel_name}': 403 Forbidden - Geo-blocked HLS stream - URL: {url}")
                return True, url, 'geo_blocked'
            elif response.status_code == 404:
                logging.warning(f"Channel '{channel_name}': 404 Not Found - HLS stream - URL: {url}")
                return False, url, 'not_found'
            else:
                logging.warning(f"Channel '{channel_name}': HTTP {response.status_code} - HLS stream - URL: {url}")
                return False, url, f'http_{response.status_code}'
        except requests.RequestException as e:
            logging.debug(f"Channel '{channel_name}': HLS validation failed - URL: {url} - Error: {e}")
        
        # Fallback to regular URL validation
        return self.validate_regular_url(url, headers, timeout, channel_name)

    def validate_regular_url(self, url, headers, timeout, channel_name="Unknown Channel"):
        """
        Validate regular URLs with detailed status logging.
        
        Args:
            url (str): URL to validate
            headers (dict): Request headers
            timeout (int): Request timeout
            channel_name (str): Channel name for detailed logging
            
        Returns:
            tuple: (is_active, final_url, status_info)
        """
        # Try HEAD request first (faster)
        try:
            response = requests.head(url, headers=headers, timeout=timeout, allow_redirects=True)
            if response.status_code < 400:
                logging.info(f"Channel '{channel_name}': Active (HEAD) - URL: {url}")
                return True, response.url, 'active'
            elif response.status_code == 403:
                logging.info(f"Channel '{channel_name}': 403 Forbidden - Geo-blocked (HEAD) - URL: {url}")
                return True, url, 'geo_blocked'
            elif response.status_code == 404:
                logging.warning(f"Channel '{channel_name}': 404 Not Found (HEAD) - URL: {url}")
                return False, url, 'not_found'
        except requests.RequestException:
            pass
        
        # Try GET request as fallback
        try:
            with requests.get(url, headers=headers, timeout=timeout, stream=True) as response:
                if response.status_code < 400:
                    logging.info(f"Channel '{channel_name}': Active (GET) - URL: {url}")
                    return True, response.url, 'active'
                elif response.status_code == 403:
                    logging.info(f"Channel '{channel_name}': 403 Forbidden - Geo-blocked (GET) - URL: {url}")
                    return True, url, 'geo_blocked'
                elif response.status_code == 404:
                    logging.warning(f"Channel '{channel_name}': 404 Not Found (GET) - URL: {url}")
                    return False, url, 'not_found'
                else:
                    logging.warning(f"Channel '{channel_name}': HTTP {response.status_code} (GET) - URL: {url}")
                    return False, url, f'http_{response.status_code}'
        except requests.RequestException as e:
            logging.debug(f"Channel '{channel_name}': Regular validation failed - URL: {url} - Error: {e}")
        
        # Try protocol switching as last resort
        try:
            alt_url = url.replace('http://', 'https://') if url.startswith('http://') else url.replace('https://', 'http://')
            if alt_url != url:  # Only try if URL actually changed
                response = requests.head(alt_url, timeout=timeout, headers=headers, allow_redirects=True)
                if response.status_code < 400:
                    logging.info(f"Channel '{channel_name}': Active (HEAD, switched protocol) - URL: {alt_url}")
                    return True, alt_url, 'active'
                elif response.status_code == 403:
                    logging.info(f"Channel '{channel_name}': 403 Forbidden - Geo-blocked (HEAD, switched protocol) - URL: {alt_url}")
                    return True, alt_url, 'geo_blocked'
        except requests.RequestException:
            pass
        
        # Mark as inactive
        logging.warning(f"Channel '{channel_name}': All validation methods failed - URL: {url}")
        return False, url, 'inactive'

    def detect_content_language(self, text):
        """
        Detect content language based on text analysis.
        
        Args:
            text (str): Text to analyze
            
        Returns:
            str: Detected language code
        """
        # Simple language detection based on common words
        french_indicators = ['télé', 'québec', 'canada', 'français', 'nouvelles', 'radio']
        english_indicators = ['news', 'tv', 'channel', 'live', 'stream', 'english']
        
        text_lower = text.lower()
        french_count = sum(1 for indicator in french_indicators if indicator in text_lower)
        english_count = sum(1 for indicator in english_indicators if indicator in text_lower)
        
        if french_count > english_count:
            return 'fr'
        elif english_count > french_count:
            return 'en'
        else:
            return 'unknown'

    def extract_quality_info(self, name):
        """
        Extract quality information from channel name.
        
        Args:
            name (str): Channel name
            
        Returns:
            tuple: (quality, resolution)
        """
        quality_patterns = {
            '4K': '2160p', 'UHD': '2160p',
            '1080p': '1080p', 'HD': '1080p', 'FHD': '1080p',
            '720p': '720p', 'HD720': '720p',
            '480p': '480p', 'SD': '480p',
            '360p': '360p', '240p': '240p'
        }
        
        name_upper = name.upper()
        for pattern, resolution in quality_patterns.items():
            if pattern in name_upper:
                return pattern, resolution
                
        return 'Unknown', 'Unknown'

    def deduplicate_channels(self):
        """
        Remove duplicate channels based on URL and name similarity.
        Keeps the highest quality version when duplicates are found.
        """
        if not self.enable_deduplication:
            return
            
        logging.info("Starting channel deduplication process")
        original_count = sum(len(channels) for channels in self.channels.values())
        
        for group_name in list(self.channels.keys()):
            channels = self.channels[group_name]
            if len(channels) <= 1:
                continue
                
            # Group channels by similarity
            unique_channels = []
            duplicates = []
            
            for channel in channels:
                is_duplicate = False
                
                for existing in unique_channels:
                    # Check for URL duplicates
                    if channel['url'] == existing['url']:
                        is_duplicate = True
                        duplicates.append(channel)
                        break
                        
                    # Check for name similarity (fuzzy matching)
                    if self.calculate_name_similarity(channel['name'], existing['name']) > 0.8:
                        # Keep the one with better quality
                        channel_quality = self.extract_quality_info(channel['name'])[1]
                        existing_quality = self.extract_quality_info(existing['name'])[1]
                        
                        if self.compare_quality(channel_quality, existing_quality) > 0:
                            # Replace existing with current (better quality)
                            duplicates.append(existing)
                            unique_channels.remove(existing)
                            unique_channels.append(channel)
                        else:
                            duplicates.append(channel)
                        is_duplicate = True
                        break
                
                if not is_duplicate:
                    unique_channels.append(channel)
            
            self.channels[group_name] = unique_channels
            self.duplicate_channels.extend(duplicates)
        
        final_count = sum(len(channels) for channels in self.channels.values())
        removed_count = original_count - final_count
        
        if removed_count > 0:
            logging.info(f"Deduplication complete: Removed {removed_count} duplicate channels")

    def calculate_name_similarity(self, name1, name2):
        """
        Calculate similarity between two channel names.
        
        Args:
            name1 (str): First channel name
            name2 (str): Second channel name
            
        Returns:
            float: Similarity score (0.0 to 1.0)
        """
        # Simple Jaccard similarity based on words
        words1 = set(re.findall(r'\w+', name1.lower()))
        words2 = set(re.findall(r'\w+', name2.lower()))
        
        if not words1 and not words2:
            return 1.0
        if not words1 or not words2:
            return 0.0
            
        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))
        
        return intersection / union if union > 0 else 0.0

    def compare_quality(self, quality1, quality2):
        """
        Compare two quality strings and return which is better.
        
        Args:
            quality1 (str): First quality
            quality2 (str): Second quality
            
        Returns:
            int: 1 if quality1 is better, -1 if quality2 is better, 0 if equal
        """
        quality_order = ['2160p', '1080p', '720p', '480p', '360p', '240p', 'Unknown']
        
        try:
            index1 = quality_order.index(quality1)
        except ValueError:
            index1 = len(quality_order) - 1
            
        try:
            index2 = quality_order.index(quality2)
        except ValueError:
            index2 = len(quality_order) - 1
        
        if index1 < index2:
            return 1
        elif index1 > index2:
            return -1
        else:
            return 0

    def test_cuisine_detection(self, lines):
        """
        Detect and count specific content types in the playlist for analytics.
        
        Args:
            lines (list): Lines from the playlist
        """
        cuisine_lines = sum(1 for line in lines if 'cuisine' in line.lower())
        zeste_lines = sum(1 for line in lines if 'zeste' in line.lower())
        
        if cuisine_lines > 0 or zeste_lines > 0:
            logging.info(f"Content detection - CUISINE: {cuisine_lines} | ZESTE: {zeste_lines}")

    def parse_and_store(self, lines, source_url, metadata=None):
        """
        Parse M3U playlist content and store channel information with comprehensive processing.
        
        Args:
            lines (list): Playlist lines to parse
            source_url (str): Source URL for reference
            metadata (dict): Additional metadata about the source
        """
        current_channel = {}
        channel_count = 0
        total_extinf_lines = 0
        group_occurrences = defaultdict(int)
        parsing_errors = []
        
        # Progress tracking
        total_lines = len(lines)
        progress_interval = max(100, total_lines // 10)
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Progress logging
            if line_num % progress_interval == 0:
                progress = (line_num / total_lines) * 100
                logging.info(f"Parsing progress: {progress:.1f}% ({line_num}/{total_lines} lines)")
            
            # Process EXTINF lines with comprehensive attribute extraction
            # FIXED: Handle both '#EXTINF:' and 'EXTINF:' patterns (Cuisine fix)
            if line.startswith('#EXTINF:') or line.startswith('EXTINF:'):
                total_extinf_lines += 1
                
                try:
                    # Extract all attributes using comprehensive regex patterns
                    attributes = self.extract_extinf_attributes(line)
                    
                    # Extract and validate logo URL
                    logo = attributes.get('tvg-logo', self.default_logo)
                    if logo and not logo.startswith(('http://', 'https://')):
                        logo = self.default_logo
                    
                    # Extract group with robust handling
                    group = "Uncategorized"
                    extracted_group = attributes.get('group-title', '').strip()
                    if extracted_group and not extracted_group.isspace():
                        group = extracted_group
                        # Normalize specific group names (Cuisine fix)
                        if group.lower() == 'cuisine':
                            group = 'Cuisine'
                    
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
                    
                    # Extract channel name with fallback
                    name = "Unnamed Channel"
                    comma_match = re.search(r',(.+)$', line)
                    if comma_match:
                        name = comma_match.group(1).strip()
                    
                    # Extract additional metadata
                    quality, resolution = self.extract_quality_info(name)
                    language = self.detect_content_language(name)
                    
                    # Create comprehensive channel object
                    current_channel = {
                        'name': name,
                        'logo': logo,
                        'group': group,
                        'source': source_url,
                        'line_num': line_num,
                        'quality': quality,
                        'resolution': resolution,
                        'language': language,
                        'attributes': attributes,
                        'added_timestamp': datetime.now().isoformat()
                    }
                    
                except Exception as e:
                    parsing_errors.append({
                        'line_num': line_num,
                        'line': line[:100],
                        'error': str(e)
                    })
                    current_channel = {}
                    
            elif line and not line.startswith('#') and current_channel:
                # Process stream URLs with validation
                if line.startswith(('http://', 'https://')):
                    # Validate and clean URL
                    clean_url = self.clean_and_validate_url(line)
                    if clean_url and clean_url not in self.seen_urls:
                        self.seen_urls.add(clean_url)
                        current_channel['url'] = clean_url
                        
                        # Add URL metadata
                        current_channel['url_domain'] = urlparse(clean_url).netloc
                        current_channel['is_hls'] = clean_url.endswith('.m3u8') or 'hls' in clean_url.lower()
                        
                        # Store channel
                        self.channels[current_channel['group']].append(current_channel)
                        channel_count += 1
                        self.channels_processed += 1
                else:
                    self.skipped_non_http_count += 1
                
                current_channel = {}
        
        # Log parsing results
        logging.info(f"Parsing complete: {channel_count} channels added from {source_url}")
        logging.info(f"Total EXTINF lines processed: {total_extinf_lines}")
        logging.info(f"Skipped non-HTTP URLs: {self.skipped_non_http_count}")
        
        if parsing_errors:
            logging.warning(f"Encountered {len(parsing_errors)} parsing errors")
            for error in parsing_errors[:5]:  # Log first 5 errors
                logging.warning(f"Line {error['line_num']}: {error['error']}")
        
        # Log group statistics
        logging.info("Group distribution:")
        for group, count in sorted(group_occurrences.items(), key=lambda x: x[1], reverse=True):
            logging.info(f"  - {group}: {count} channels")
        
        # Update global statistics
        self.statistics['total_lines_processed'] += total_lines
        self.statistics['total_channels_found'] += channel_count
        self.statistics['parsing_errors'] += len(parsing_errors)

    def extract_extinf_attributes(self, line):
        """
        Extract all attributes from an EXTINF line using comprehensive regex.
        
        Args:
            line (str): EXTINF line to parse
            
        Returns:
            dict: Extracted attributes
        """
        attributes = {}
        
        # Define attribute patterns
        patterns = {
            'tvg-id': r'tvg-id="([^"]*)"',
            'tvg-name': r'tvg-name="([^"]*)"',
            'tvg-logo': r'tvg-logo="([^"]*)"',
            'group-title': r'group-title="([^"]*)"',
            'tvg-country': r'tvg-country="([^"]*)"',
            'tvg-language': r'tvg-language="([^"]*)"',
            'tvg-url': r'tvg-url="([^"]*)"',
            'radio': r'radio="([^"]*)"',
            'audio-track': r'audio-track="([^"]*)"'
        }
        
        # Extract each attribute
        for attr_name, pattern in patterns.items():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                attributes[attr_name] = match.group(1).strip()
        
        return attributes

    def clean_and_validate_url(self, url):
        """
        Clean and validate streaming URL.
        
        Args:
            url (str): URL to clean and validate
            
        Returns:
            str: Cleaned URL or None if invalid
        """
        if not url or not isinstance(url, str):
            return None
            
        # Clean whitespace and common encoding issues
        url = url.strip()
        url = re.sub(r'\s+', '', url)  # Remove all whitespace
        
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            return None
            
        try:
            # Parse and validate URL components
            parsed = urlparse(url)
            if not parsed.netloc:
                return None
                
            # Reconstruct clean URL
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean_url += f"?{parsed.query}"
            if parsed.fragment:
                clean_url += f"#{parsed.fragment}"
                
            return clean_url
            
        except Exception:
            return None

    def sort_channels_by_quality(self):
        """Sort channels within each group by quality preference."""
        if not self.enable_quality_sorting:
            return
            
        for group_name in self.channels:
            channels = self.channels[group_name]
            
            def quality_sort_key(channel):
                resolution = channel.get('resolution', 'Unknown')
                try:
                    return self.quality_preferences.index(resolution)
                except ValueError:
                    return len(self.quality_preferences)  # Unknown quality goes last
            
            self.channels[group_name] = sorted(channels, key=quality_sort_key)

    def filter_active_channels(self):
        """
        Filter channels by checking URL availability with detailed validation logging.
        Uses concurrent processing for performance optimization.
        """
        if not self.check_links:
            logging.info("Link validation disabled - skipping active channel filtering")
            return
        
        logging.info("Starting comprehensive link validation process")
        start_time = time.time()
        
        # Collect all unique URLs to check
        url_to_channels = defaultdict(list)
        for group, channels in self.channels.items():
            for channel in channels:
                url_to_channels[channel['url']].append((group, channel))
        
        total_urls = len(url_to_channels)
        logging.info(f"Total channels to check: {sum(len(channels) for channels in url_to_channels.values())}")
        logging.info(f"Validating {total_urls} unique URLs")
        
        active_channels = defaultdict(list)
        validation_results = {}
        geo_blocked_count = 0
        
        # Process URLs concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all validation tasks
            future_to_url = {}
            for url, channels in url_to_channels.items():
                # Use the first channel's name for logging
                channel_name = channels[0][1]['name']
                future = executor.submit(self.check_link_active, url, channel_name)
                future_to_url[future] = url
            
            # Process results as they complete
            completed = 0
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                completed += 1
                
                # Progress reporting
                if completed % 10 == 0 or completed == total_urls:
                    progress = (completed / total_urls) * 100
                    elapsed = time.time() - start_time
                    logging.info(f"Validation progress: {progress:.1f}% ({completed}/{total_urls}) - {elapsed:.1f}s elapsed")
                
                try:
                    is_active, final_url, status = future.result()
                    validation_results[url] = (is_active, final_url, status)
                    
                    # Add channels with active URLs
                    if is_active:
                        for group, channel in url_to_channels[url]:
                            # Update channel with final URL if it changed
                            if final_url != url:
                                channel['url'] = final_url
                                channel['original_url'] = url
                            
                            channel['validation_status'] = status
                            channel['validation_timestamp'] = datetime.now().isoformat()
                            
                            # Tag geo-blocked channels
                            if status == 'geo_blocked':
                                if not channel['name'].endswith('[Geo-blocked]'):
                                    original_name = channel['name']
                                    channel['name'] = f"{channel['name']} [Geo-blocked]"
                                    logging.info(f"Tagged as geo-blocked: {channel['name']} - URL: {channel['url']}")
                                    geo_blocked_count += 1
                            
                            active_channels[group].append(channel)
                    else:
                        # Log inactive channels
                        for group, channel in url_to_channels[url]:
                            logging.warning(f"Channel '{channel['name']}' is inactive ({status}) - URL: {url}")
                    
                except Exception as e:
                    logging.error(f"Validation error for {url}: {e}")
                    validation_results[url] = (False, url, f'error: {e}')
        
        # Update channels with filtered results
        original_count = sum(len(ch) for ch in self.channels.values())
        self.channels = active_channels
        final_count = sum(len(ch) for ch in self.channels.values())
        
        # Log detailed validation statistics
        elapsed_time = time.time() - start_time
        active_count = sum(1 for is_active, _, _ in validation_results.values() if is_active)
        
        logging.info(f"Link validation complete in {format_duration(int(elapsed_time))}")
        logging.info(f"Results: {active_count}/{total_urls} URLs active ({(active_count/total_urls*100):.1f}%)")
        logging.info(f"Channels: {final_count}/{original_count} remaining ({(final_count/original_count*100):.1f}%)")
        logging.info(f"Active channels after filtering: {final_count}")
        logging.info(f"Geo-blocked channels detected: {geo_blocked_count}")
        
        # Update statistics
        self.statistics['urls_validated'] = total_urls
        self.statistics['active_urls'] = active_count
        self.statistics['geo_blocked_urls'] = geo_blocked_count
        self.statistics['validation_time'] = elapsed_time

    def process_sources(self, source_urls):
        """
        Process all source URLs with comprehensive pipeline.
        
        Args:
            source_urls (list): List of source URLs to process
        """
        logging.info(f"Starting processing of {len(source_urls)} source URLs")
        self.start_time = time.time()
        
        # Clear existing data
        self.channels.clear()
        self.seen_urls.clear()
        self.url_status_cache.clear()
        self.duplicate_channels.clear()
        self.failed_urls.clear()
        
        all_m3u_urls = set()
        
        # Process each source
        for i, url in enumerate(source_urls, 1):
            logging.info(f"Processing source {i}/{len(source_urls)}: {url}")
            
            content, lines, metadata = self.fetch_content_with_retry(url)
            
            if not lines:
                logging.warning(f"No content retrieved from {url}")
                continue
            
            # Handle different content types
            if url.endswith('.html') or metadata.get('content_type', '').startswith('text/html'):
                # Extract M3U URLs from HTML
                extracted_urls = self.extract_stream_urls_from_html(content, url)
                all_m3u_urls.update(extracted_urls)
                logging.info(f"Extracted {len(extracted_urls)} potential M3U URLs from HTML")
            else:
                # Process as M3U content
                self.test_cuisine_detection(lines)
                self.parse_and_store(lines, url, metadata)
        
        # Process extracted M3U URLs
        if all_m3u_urls:
            logging.info(f"Processing {len(all_m3u_urls)} extracted M3U URLs")
            for m3u_url in all_m3u_urls:
                content, lines, metadata = self.fetch_content_with_retry(m3u_url)
                if lines:
                    self.test_cuisine_detection(lines)
                    self.parse_and_store(lines, m3u_url, metadata)
        
        # Post-processing pipeline
        total_parsed = sum(len(ch) for ch in self.channels.values())
        logging.info(f"PHASE 1 COMPLETE: {total_parsed} channels parsed across {len(self.channels)} groups")
        
        # Special reporting for important channel types
        important_groups = ['Cuisine', 'Actualités', 'Sports', 'Généraliste']
        for group in important_groups:
            if group in self.channels:
                count = len(self.channels[group])
                logging.info(f"{group} channels found: {count}")
        
        # Apply post-processing filters and optimizations
        if total_parsed > 0:
            logging.info("Starting post-processing pipeline")
            
            # Remove duplicates
            self.deduplicate_channels()
            
            # Sort by quality
            self.sort_channels_by_quality()
            
            # Validate links if enabled
            if self.check_links:
                self.filter_active_channels()
        
        # Final statistics
        final_count = sum(len(ch) for ch in self.channels.values())
        processing_time = time.time() - self.start_time
        
        logging.info(f"Processing complete: {final_count} final channels in {format_duration(int(processing_time))}")
        logging.info(f"Groups: {', '.join(sorted(self.channels.keys()))}")
        
        # Update global statistics
        self.statistics['total_processing_time'] = processing_time
        self.statistics['final_channel_count'] = final_count
        self.statistics['source_urls_processed'] = len(source_urls)

    def export_m3u(self, filename="LiveTV.m3u"):
        """Export channels to standard M3U playlist format with enhanced metadata."""
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            # Write M3U header with metadata
            f.write('#EXTM3U\n')
            f.write(f'#PLAYLIST:M3U Playlist for {self.country}\n')
            f.write(f'#EXTENC:UTF-8\n')
            f.write(f'#CREATED:{datetime.now().isoformat()}\n')
            f.write(f'#TOTAL-CHANNELS:{sum(len(ch) for ch in self.channels.values())}\n')
            f.write('\n')
            
            # Write channels grouped by category
            for group, channels in sorted(self.channels.items()):
                f.write(f'# --- {group} ({len(channels)} channels) ---\n')
                
                for channel in channels:
                    # Build EXTINF line with comprehensive attributes
                    extinf_parts = ['#EXTINF:-1']
                    
                    # Add standard attributes
                    if channel.get('logo'):
                        extinf_parts.append(f'tvg-logo="{channel["logo"]}"')
                    extinf_parts.append(f'group-title="{group}"')
                    
                    # Add optional attributes if available
                    if channel.get('attributes'):
                        for attr, value in channel['attributes'].items():
                            if attr not in ['group-title', 'tvg-logo'] and value:
                                extinf_parts.append(f'{attr}="{value}"')
                    
                    # Add quality and language info
                    if channel.get('resolution') and channel['resolution'] != 'Unknown':
                        extinf_parts.append(f'tvg-resolution="{channel["resolution"]}"')
                    if channel.get('language') and channel['language'] != 'unknown':
                        extinf_parts.append(f'tvg-language="{channel["language"]}"')
                    
                    # Write EXTINF line and URL
                    f.write(f'{" ".join(extinf_parts)},{channel["name"]}\n')
                    f.write(f'{channel["url"]}\n')
                
                f.write('\n')
        
        logging.info(f"Exported M3U playlist to {filepath}")
        return filepath

    def export_txt(self, filename="LiveTV.txt"):
        """Export channels to human-readable text format with detailed information."""
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            # Write header
            f.write(f"Live TV Channel List for {self.country}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Channels: {sum(len(ch) for ch in self.channels.values())}\n")
            f.write(f"Total Groups: {len(self.channels)}\n")
            f.write("=" * 80 + "\n\n")
            
            # Write channels by group
            for group, channels in sorted(self.channels.items()):
                f.write(f"GROUP: {group} ({len(channels)} channels)\n")
                f.write("-" * 60 + "\n")
                
                for i, channel in enumerate(channels, 1):
                    f.write(f"{i:3d}. {channel['name']}\n")
                    f.write(f"     URL: {channel['url']}\n")
                    f.write(f"     Logo: {channel.get('logo', 'N/A')}\n")
                    f.write(f"     Source: {channel['source']}\n")
                    
                    # Add additional metadata if available
                    if channel.get('quality') and channel['quality'] != 'Unknown':
                        f.write(f"     Quality: {channel['quality']}\n")
                    if channel.get('language') and channel['language'] != 'unknown':
                        f.write(f"     Language: {channel['language']}\n")
                    if channel.get('validation_status'):
                        f.write(f"     Status: {channel['validation_status']}\n")
                    
                    f.write("\n")
                
                f.write("\n")
        
        logging.info(f"Exported text format to {filepath}")
        return filepath

    def export_json(self, filename="LiveTV.json"):
        """Export channels to JSON format with comprehensive metadata."""
        filepath = os.path.join(self.output_dir, filename)
        
        # Prepare timezone-aware timestamp
        mumbai_tz = pytz.timezone('Asia/Kolkata')
        current_time = datetime.now(mumbai_tz).strftime('%Y-%m-%d %H:%M:%S')
        
        # Build comprehensive JSON structure
        json_data = {
            "metadata": {
                "generated_at": current_time,
                "country": self.country,
                "total_channels": sum(len(ch) for ch in self.channels.values()),
                "total_groups": len(self.channels),
                "processing_time": self.statistics.get('total_processing_time', 0),
                "validation_enabled": self.check_links,
                "deduplication_enabled": self.enable_deduplication
            },
            "statistics": dict(self.statistics),
            "configuration": {
                "excluded_groups": self.excluded_groups,
                "quality_preferences": self.quality_preferences,
                "language_preferences": self.language_preferences
            },
            "channels": dict(self.channels),
            "failed_urls": self.failed_urls[:10],  # Include first 10 failed URLs
            "duplicate_channels": len(self.duplicate_channels)
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, ensure_ascii=False, indent=2, default=str)
        
        logging.info(f"Exported JSON to {filepath}")
        return filepath

    def export_custom(self, filename="LiveTV"):
        """Export channels to custom application format."""
        filepath = os.path.join(self.output_dir, filename)
        
        custom_data = []
        for group, channels in self.channels.items():
            for channel in channels:
                custom_entry = {
                    "name": channel['name'],
                    "type": group,
                    "url": channel['url'],
                    "img": channel.get('logo', ''),
                    "quality": channel.get('resolution', 'Unknown'),
                    "language": channel.get('language', 'unknown'),
                    "active": channel.get('validation_status', 'unknown') != 'inactive'
                }
                custom_data.append(custom_entry)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(custom_data, f, ensure_ascii=False, indent=2)
        
        logging.info(f"Exported custom format to {filepath}")
        return filepath

    def export_csv(self, filename="LiveTV.csv"):
        """Export channels to CSV format for spreadsheet applications."""
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['name', 'group', 'url', 'logo', 'quality', 'resolution', 
                         'language', 'source', 'status', 'added_timestamp']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for group, channels in self.channels.items():
                for channel in channels:
                    row = {
                        'name': channel['name'],
                        'group': group,
                        'url': channel['url'],
                        'logo': channel.get('logo', ''),
                        'quality': channel.get('quality', 'Unknown'),
                        'resolution': channel.get('resolution', 'Unknown'),
                        'language': channel.get('language', 'unknown'),
                        'source': channel['source'],
                        'status': channel.get('validation_status', 'unknown'),
                        'added_timestamp': channel.get('added_timestamp', '')
                    }
                    writer.writerow(row)
        
        logging.info(f"Exported CSV to {filepath}")
        return filepath

    def export_xmltv(self, filename="LiveTV.xml"):
        """Export channels to XMLTV format for EPG applications."""
        filepath = os.path.join(self.output_dir, filename)
        
        # Create XMLTV structure
        root = ET.Element("tv")
        root.set("source-info-name", f"Live TV Collector - {self.country}")
        root.set("generator-info-name", "M3UCollector")
        
        # Add channels
        for group, channels in self.channels.items():
            for channel in channels:
                channel_elem = ET.SubElement(root, "channel")
                channel_elem.set("id", f"ch_{hash(channel['url']) & 0x7FFFFFFF}")
                
                # Display name
                display_name = ET.SubElement(channel_elem, "display-name")
                display_name.text = channel['name']
                
                # Icon
                if channel.get('logo'):
                    icon = ET.SubElement(channel_elem, "icon")
                    icon.set("src", channel['logo'])
                
                # URL (custom extension)
                url_elem = ET.SubElement(channel_elem, "url")
                url_elem.text = channel['url']
                
                # Group (custom extension)
                group_elem = ET.SubElement(channel_elem, "group")
                group_elem.text = group
        
        # Write XML file
        tree = ET.ElementTree(root)
        tree.write(filepath, encoding='utf-8', xml_declaration=True)
        
        logging.info(f"Exported XMLTV to {filepath}")
        return filepath

    def export_all_formats(self):
        """Export channels to all supported formats."""
        exported_files = []
        export_methods = [
            ('M3U', self.export_m3u),
            ('TXT', self.export_txt),
            ('JSON', self.export_json),
            ('Custom', self.export_custom),
            ('CSV', self.export_csv),
            ('XMLTV', self.export_xmltv)
        ]
        
        for format_name, export_method in export_methods:
            try:
                filepath = export_method()
                exported_files.append((format_name, filepath))
                logging.info(f"Successfully exported {format_name} format")
            except Exception as e:
                logging.error(f"Failed to export {format_name} format: {e}")
        
        return exported_files

    def generate_report(self, filename="processing_report.txt"):
        """Generate a comprehensive processing report."""
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"M3U Collector Processing Report\n")
            f.write(f"Country: {self.country}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            
            # Processing statistics
            f.write("PROCESSING STATISTICS\n")
            f.write("-" * 25 + "\n")
            for key, value in self.statistics.items():
                f.write(f"{key.replace('_', ' ').title()}: {value}\n")
            f.write("\n")
            
            # Channel statistics by group
            f.write("CHANNEL DISTRIBUTION\n")
            f.write("-" * 20 + "\n")
            for group, channels in sorted(self.channels.items(), key=lambda x: len(x[1]), reverse=True):
                f.write(f"{group}: {len(channels)} channels\n")
            f.write("\n")
            
            # Failed URLs
            if self.failed_urls:
                f.write("FAILED URLS\n")
                f.write("-" * 11 + "\n")
                for failed in self.failed_urls[:10]:
                    f.write(f"URL: {failed['url']}\n")
                    f.write(f"Error: {failed['error']}\n\n")
            
            # Configuration
            f.write("CONFIGURATION\n")
            f.write("-" * 13 + "\n")
            f.write(f"Link checking: {self.check_links}\n")
            f.write(f"Deduplication: {self.enable_deduplication}\n")
            f.write(f"Quality sorting: {self.enable_quality_sorting}\n")
            f.write(f"Excluded groups: {len(self.excluded_groups)}\n")
        
        logging.info(f"Generated processing report: {filepath}")
        return filepath

    def get_excluded_groups_info(self):
        """Get information about excluded groups configuration."""
        return {
            'excluded_groups': self.excluded_groups,
            'excluded_count': len(self.excluded_groups)
        }

def main():
    """
    Main execution function with comprehensive configuration and detailed validation logging.
    """
    logging.info("Starting M3U Collector with full functionality")
    
    # Get server geolocation for analytics
    server_location = get_server_geolocation()
    
    # Configuration for excluded groups (content filtering)
    excluded_groups = [
        "Argentina", "Austria", "Brazil", "Chile", "Denmark", "Germany", 
        "India", "Italy", "Mexico", "Norway", "South Korea", "Spain", 
        "Sweden", "Switzerland", "United Kingdom", "United States",
        "Offline", "Test", "Demo", "Shopping", "Teleshopping"
    ]
    
    # Source URLs to process
    source_urls = [
        "https://github.com/Sphinxroot/QC-TV/raw/16afc34391cf7a1dbc0b6a8273476a7d3f9ca33b/Quebec.m3u",
    ]
    
    # Advanced configuration
    config = {
        'max_workers': 15,  # Concurrent processing threads
        'request_timeout': 12,  # Request timeout in seconds
        'max_retries': 2,  # Maximum retry attempts
        'enable_deduplication': True,  # Remove duplicate channels
        'enable_quality_sorting': True,  # Sort by quality preference
        'quality_preferences': ['4K', '1080p', '720p', '480p', '360p'],
        'language_preferences': ['fr', 'en']  # French first, then English
    }
    
    # Initialize collector with comprehensive configuration
    collector = M3UCollector(
        country="Mikhoul", 
        check_links=True,  # ENABLE DETAILED VALIDATION LOGGING
        excluded_groups=excluded_groups,
        config=config
    )
    
    # Log configuration
    excluded_info = collector.get_excluded_groups_info()
    logging.info(f"Excluded groups: {excluded_info['excluded_count']} | {', '.join(excluded_groups[:5])}{'...' if len(excluded_groups) > 5 else ''}")
    
    try:
        # Process all sources
        collector.process_sources(source_urls)
        
        # Export to all formats
        logging.info("Exporting to all supported formats")
        exported_files = collector.export_all_formats()
        
        # Generate processing report
        collector.generate_report()
        
        # Final statistics and summary
        total_channels = sum(len(ch) for ch in collector.channels.values())
        total_time = time.time() - collector.start_time
        mumbai_time = datetime.now(pytz.timezone('Asia/Kolkata'))
        
        logging.info(f"Processing completed successfully!")
        logging.info(f"Final Results:")
        logging.info(f"  - Total channels: {total_channels}")
        logging.info(f"  - Total groups: {len(collector.channels)}")
        logging.info(f"  - Processing time: {format_duration(int(total_time))}")
        logging.info(f"  - Exported formats: {len(exported_files)}")
        logging.info(f"  - Timestamp: {mumbai_time}")
        
        # Log group summary
        if collector.channels:
            logging.info("Group summary:")
            for group in sorted(collector.channels.keys()):
                count = len(collector.channels[group])
                logging.info(f"  - {group}: {count} channels")
        
        # Server location for analytics
        if server_location:
            logging.info(f"Processing performed from: {server_location['country']} ({server_location['country_code']})")
            
    except Exception as e:
        logging.error(f"Critical error during processing: {e}")
        raise

if __name__ == "__main__":
    main()
