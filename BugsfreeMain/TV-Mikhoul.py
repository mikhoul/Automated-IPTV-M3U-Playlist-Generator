import requests
import json
import os
import re
from urllib.parse import urlparse, urljoin
from collections import defaultdict
from datetime import datetime
import pytz
import concurrent.futures
import threading
import logging
import time
import hashlib
import html
from bs4 import BeautifulSoup

class ValidationColorFormatter(logging.Formatter):
    """Enhanced logging formatter with FIXED keyword filtering - no color overlap."""
    
    # ANSI escape codes for colors
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    
    # Color definitions - FIXED: Single red shade and lighter gray
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"
    MAGENTA = "\x1b[35m"
    CYAN = "\x1b[36m"
    WHITE = "\x1b[37m"
    BRIGHT_RED = "\x1b[91m"
    BRIGHT_GREEN = "\x1b[38;5;82m"
    BRIGHT_YELLOW = "\x1b[93m"
    BRIGHT_BLUE = "\x1b[94m"
    BRIGHT_CYAN = "\x1b[96m"
    
    # FIXED: Single red shade (bloody) and lighter gray for URLs
    INACTIVE_RED = "\x1b[38;5;203m"  # Single consistent red for INACTIVE
    LIGHT_GRAY = "\x1b[38;5;255m"   # Light gray for stream URLs
    LIGHT_ORANGE = "\x1b[38;5;214m"  # Consistent light orange for geo-blocking
    PALE_YELLOW = "\x1b[38;5;230m"   # NEW: Very pale yellow for source URLs
    
    # Map log levels to colors (not used anymore since we remove INFO/WARNING prefixes)
    LEVEL_COLORS = {
        logging.DEBUG: CYAN,
        logging.INFO: BRIGHT_BLUE,
        logging.WARNING: BRIGHT_YELLOW,
        logging.ERROR: BRIGHT_RED,
        logging.CRITICAL: BOLD + BRIGHT_RED
    }
    
    # FIXED: Proper keyword ordering to prevent overlap - INACTIVE must come before ACTIVE
    KEYWORD_COLORS = {
        # FIXED: Complete word coloring with proper priority ordering
        'Successfully': BRIGHT_GREEN,  # Complete word
        
        # Negative status - SINGLE RED SHADE (MUST COME FIRST to prevent ACTIVE overlap)
        'INACTIVE': BOLD + INACTIVE_RED,  # FIXED: Must be processed before ACTIVE
        'inactive': INACTIVE_RED,
        'OFFLINE': BOLD + INACTIVE_RED,  # FIXED: Added OFFLINE in red
        'offline': INACTIVE_RED,
        'All validation methods failed': INACTIVE_RED,
        'Failed': INACTIVE_RED,
        'FAILED': BOLD + INACTIVE_RED,
        
        # Positive status - GREEN ONLY (MUST COME AFTER negative status)
        'ACTIVE HLS stream': BRIGHT_GREEN,
        'ACTIVE (HEAD)': BRIGHT_GREEN,
        'ACTIVE (GET)': BRIGHT_GREEN,
        'ACTIVE': BRIGHT_GREEN,  # FIXED: Comes after INACTIVE to prevent overlap
        'SUCCESS': BRIGHT_GREEN,
        'Success': BRIGHT_GREEN,
        
        # Error codes - SINGLE RED SHADE
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
        'geo_blocked': LIGHT_ORANGE,
        '403 Forbidden': LIGHT_ORANGE,
        
        # Channel processing
        'CUISINE': BOLD + MAGENTA,
        'Cuisine': MAGENTA,
        
        # Validation progress
        'Validation progress': BLUE,
        'Starting comprehensive link validation': BOLD + BLUE,
        'Link validation complete': BOLD + GREEN,
        
        # HTTP status codes - SINGLE RED SHADE
        'Bad Request': INACTIVE_RED,
        'Internal Server Error': INACTIVE_RED,
        'Bad Gateway': INACTIVE_RED,
        'Service Unavailable': INACTIVE_RED,
        
        # URL prefixes (colors applied to the prefix, URLs handled separately)
        'URL:': LIGHT_GRAY,
        'SOURCE:': PALE_YELLOW,
        
        # Processing stages
        'PHASE 1 COMPLETE': BOLD + GREEN,
        'Processing complete': BOLD + GREEN,
        'Deduplication complete': GREEN,
        'Starting post-processing': BLUE,
    }
    
    def __init__(self, fmt=None, datefmt=None):
        # Remove INFO/WARNING prefixes for cleaner output
        if fmt is None:
            fmt = '%(asctime)s - %(message)s'
        super().__init__(fmt, datefmt)
    
    def format(self, record):
        # Get the formatted message without level name coloring
        message = super().format(record)
        
        # ENHANCED: Color different types of URLs with different colors
        import re
        
        # Color source URLs with pale yellow (must come first to avoid overlap)
        source_pattern = r'SOURCE:\s*(https?://[^\s]+)'
        message = re.sub(source_pattern, f'SOURCE: {self.PALE_YELLOW}\\1{self.RESET}', message)
        
        # Color stream URLs with light gray
        stream_pattern = r'URL:\s*(https?://[^\s]+)'
        message = re.sub(stream_pattern, f'URL: {self.LIGHT_GRAY}\\1{self.RESET}', message)
        
        # Apply keyword coloring with proper ordering
        sorted_keywords = []
        
        # First, add all INACTIVE-related keywords
        inactive_keywords = [(k, v) for k, v in self.KEYWORD_COLORS.items()
                           if 'INACTIVE' in k.upper() or 'OFFLINE' in k.upper()]
        sorted_keywords.extend(sorted(inactive_keywords, key=lambda x: len(x[0]), reverse=True))
        
        # Then add all other keywords except ACTIVE-only ones
        other_keywords = [(k, v) for k, v in self.KEYWORD_COLORS.items()
                         if 'INACTIVE' not in k.upper() and 'OFFLINE' not in k.upper()
                         and k != 'ACTIVE' and k not in ['URL:', 'SOURCE:']]  # Skip URL prefixes
        sorted_keywords.extend(sorted(other_keywords, key=lambda x: len(x[0]), reverse=True))
        
        # Finally add ACTIVE to avoid overlap with INACTIVE
        if 'ACTIVE' in self.KEYWORD_COLORS:
            sorted_keywords.append(('ACTIVE', self.KEYWORD_COLORS['ACTIVE']))
        
        # Apply coloring with word boundary protection (skip URL prefixes as they're handled above)
        for keyword, color_code in sorted_keywords:
            if keyword in message:
                if len(keyword.split()) == 1 and keyword.isalpha():
                    pattern = r'\b' + re.escape(keyword) + r'\b'
                    colored_keyword = f"{color_code}{keyword}{self.RESET}"
                    message = re.sub(pattern, colored_keyword, message)
                else:
                    colored_keyword = f"{color_code}{keyword}{self.RESET}"
                    message = message.replace(keyword, colored_keyword)
        
        return message

def setup_colored_logging():
    """Setup colored logging with fixed colors."""
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

# Configure colored logging with fixes
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
        
        # Keep it simple - just store the original list
        self.excluded_groups = excluded_groups or []
    
        # NEW: Track exclusion logging and collect summary data
        self.logged_exclusions = set()  # Track which patterns have been logged
        self.excluded_groups_summary = defaultdict(lambda: {
            'count': 0, 
            'pattern': '', 
            'sources': set(),
            'first_seen': None
        })
        
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
        
        # FIXED: Add logging lock to prevent interleaving
        self.logging_lock = threading.Lock()
        
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

    def should_exclude_group(self, group_name, source_url="Unknown"):
        """
        Simple and efficient group exclusion check with optimized logging.
        Logs only the first occurrence of each pattern and collects summary data.
        
        Args:
            group_name (str): Group name to check
            source_url (str): Source URL for tracking
            
        Returns:
            bool: True if group should be excluded
        """
        if not group_name or not self.excluded_groups:
            return False
        
        # Clean and normalize the group name
        clean_group = html.unescape(group_name.strip())
        
        # Check against each excluded group pattern
        for excluded in self.excluded_groups:
            clean_excluded = html.unescape(excluded.strip())
            
            # Simple containment check - if excluded pattern is found in group name
            if clean_excluded.lower() in clean_group.lower():
                # Log only the FIRST occurrence of this pattern
                if clean_excluded not in self.logged_exclusions:
                    with self.logging_lock:
                        # NEW: Enhanced logging to show match type
                        match_type = "EXACT" if clean_group.lower() == clean_excluded.lower() else "PARTIAL"
                        logging.info(f"\033[93mEXCLUDED GROUP DETECTED ({match_type}): '{clean_group}' (matched pattern: '{clean_excluded}')\033[0m")
                    self.logged_exclusions.add(clean_excluded)
                
                # Update summary data for final report
                self.excluded_groups_summary[clean_group]['count'] += 1
                self.excluded_groups_summary[clean_group]['pattern'] = clean_excluded
                self.excluded_groups_summary[clean_group]['sources'].add(source_url)
                if self.excluded_groups_summary[clean_group]['first_seen'] is None:
                    self.excluded_groups_summary[clean_group]['first_seen'] = datetime.now().strftime('%H:%M:%S')
                
                return True
        
        return False

    def log_exclusion_summary(self):
        """
        Log a comprehensive summary of all excluded groups with enhanced formatting.
        Highlights non-exact matches to identify potential unintended exclusions.
        """
        if not self.excluded_groups_summary:
            return
        
        total_excluded = sum(info['count'] for info in self.excluded_groups_summary.values())
        unique_patterns = len(self.logged_exclusions)
        unique_groups = len(self.excluded_groups_summary)
        
        # NEW: Identify non-exact matches
        non_exact_matches = []
        exact_matches = []
        
        for group_name, info in self.excluded_groups_summary.items():
            if group_name.lower().strip() != info['pattern'].lower().strip():
                non_exact_matches.append((group_name, info))
            else:
                exact_matches.append((group_name, info))
        
        with self.logging_lock:
            logging.info(f"\033[96m{'='*80}\033[0m")
            logging.info(f"\033[1m\033[96mEXCLUSION SUMMARY REPORT\033[0m")
            logging.info(f"\033[96m{'='*80}\033[0m")
            logging.info(f"\033[93mTotal excluded channels: {total_excluded}\033[0m")
            logging.info(f"\033[93mUnique excluded patterns: {unique_patterns}\033[0m")
            logging.info(f"\033[93mUnique excluded groups: {unique_groups}\033[0m")
            logging.info(f"\033[93mExact matches: {len(exact_matches)}\033[0m")
            logging.info(f"\033[91mNon-exact matches: {len(non_exact_matches)}\033[0m")
            logging.info(f"\033[96m{'-'*80}\033[0m")
            
            # NEW: Show non-exact matches first (potential unintended exclusions)
            if non_exact_matches:
                logging.info(f"\033[1m\033[91m⚠️  NON-EXACT MATCHES (Potential Unintended Exclusions)\033[0m")
                logging.info(f"\033[96m{'-'*80}\033[0m")
                
                # Sort non-exact matches by count (most excluded first)
                sorted_non_exact = sorted(non_exact_matches, key=lambda x: x[1]['count'], reverse=True)
                
                for group_name, info in sorted_non_exact:
                    sources_list = list(info['sources'])
                    sources_display = sources_list[0] if len(sources_list) == 1 else f"{sources_list[0]} (+{len(sources_list)-1} more)"
                    
                    logging.info(f"\033[91m• Group:\033[0m '{group_name}'")
                    logging.info(f"  \033[93m⚠️  Matched Pattern:\033[0m '{info['pattern']}'")
                    logging.info(f"  \033[95mMatch Type:\033[0m Partial/Substring match")
                    logging.info(f"  \033[92mExcluded:\033[0m {info['count']} channels")
                    logging.info(f"  \033[94mSources:\033[0m {sources_display}")
                    logging.info(f"  \033[90mFirst seen:\033[0m {info['first_seen']}")
                    logging.info("")
            
            # Show exact matches
            if exact_matches:
                logging.info(f"\033[1m\033[92m✓ EXACT MATCHES (Intended Exclusions)\033[0m")
                logging.info(f"\033[96m{'-'*80}\033[0m")
                
                # Sort exact matches by count (most excluded first)
                sorted_exact = sorted(exact_matches, key=lambda x: x[1]['count'], reverse=True)
                
                for group_name, info in sorted_exact:
                    sources_list = list(info['sources'])
                    sources_display = sources_list[0] if len(sources_list) == 1 else f"{sources_list[0]} (+{len(sources_list)-1} more)"
                    
                    logging.info(f"\033[91m• Group:\033[0m '{group_name}'")
                    logging.info(f"  \033[95mPattern:\033[0m '{info['pattern']}'")
                    logging.info(f"  \033[92mExcluded:\033[0m {info['count']} channels")
                    logging.info(f"  \033[94mSources:\033[0m {sources_display}")
                    logging.info(f"  \033[90mFirst seen:\033[0m {info['first_seen']}")
                    logging.info("")
            
            logging.info(f"\033[96m{'='*80}\033[0m")
            
            # NEW: Summary recommendations
            if non_exact_matches:
                logging.info(f"\033[1m\033[93m💡 RECOMMENDATIONS:\033[0m")
                logging.info(f"\033[93m• Review {len(non_exact_matches)} non-exact matches above\033[0m")
                logging.info(f"\033[93m• Consider making exclusion patterns more specific\033[0m")
                logging.info(f"\033[93m• Or add these groups to exclusions if intended\033[0m")
                logging.info(f"\033[96m{'='*80}\033[0m")

    def is_redirect_service(self, url):
        """
        Detect if URL is from a known redirect service .
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if URL is from a redirect service
        """
        redirect_domains = [
            'jmp2.uk', 'tinyurl.com', 'bit.ly', 'short.link',
            'ow.ly', 'goo.gl', 't.co', 'is.gd', 'buff.ly'
        ]
        
        domain = urlparse(url).netloc.lower()
        return any(redirect_domain in domain for redirect_domain in redirect_domains)
    

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
                    response.encoding = response.encoding or 'utf-8'
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
                    js_urls = re.findall(r'["\'](https?://[^"\']*\.m3u8?[^"\']*)["\']', script.string)
                    for js_url in js_urls:
                        if self.is_valid_stream_url(js_url):
                            stream_urls.add(js_url)
        
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

    def check_link_active(self, url, channel_name="Unknown Channel", source_url="Unknown Source", timeout=None):
        """
        Comprehensive link validation with detailed logging and caching.
        
        Args:
            url (str): URL to check
            channel_name (str): Channel name for detailed logging
            source_url (str): Source URL for troubleshooting
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
            result = self.validate_hls_stream(url, headers, timeout, channel_name, source_url)
        else:
            result = self.validate_regular_url(url, headers, timeout, channel_name, source_url)
        
        # Cache the result with timestamp
        with self.lock:
            self.url_status_cache[url] = {
                'is_active': result[0],
                'url': result[1],
                'status': result[2],
                'timestamp': time.time()
            }
        
        return result

    def validate_hls_stream(self, url, headers, timeout, channel_name="Unknown Channel", source_url="Unknown Source"):
        """
        Validate HLS/M3U8 streams with ENHANCED redirect handling.
        
        Args:
            url (str): URL to validate
            headers (dict): Request headers
            timeout (int): Request timeout
            channel_name (str): Channel name for detailed logging
            source_url (str): Source URL for troubleshooting
            
        Returns:
            tuple: (is_active, final_url, status_info)
        """
        try:
            # PATCH: Enhanced redirect handling for redirect services
            if self.is_redirect_service(url):
                # Use more permissive approach for redirect services
                response = requests.get(url, headers=headers, timeout=timeout, 
                                      stream=True, allow_redirects=True)
                
                # If we get redirect service errors, try to resolve manually
                if response.status_code in [530, 503, 502, 500]:
                    try:
                        # Try with basic headers to get past redirect service
                        basic_headers = {'User-Agent': self.user_agent}
                        response = requests.get(url, headers=basic_headers, timeout=timeout,
                                              stream=True, allow_redirects=True)
                    except:
                        pass  # Continue with original response
            else:
                # Original logic for non-redirect URLs
                response = requests.get(url, headers=headers, timeout=timeout, stream=True)
            
            if response.status_code == 200:
                # Check if content looks like a valid M3U8 playlist
                content = response.text[:2048]
                if '#EXTM3U' in content or '#EXT-X-VERSION' in content:
                    with self.logging_lock:
                        logging.info(f"Channel '{channel_name}': ACTIVE HLS stream")
                        logging.info(f"URL: {url}")
                        logging.info(f"SOURCE: {source_url}")
                        logging.info("")
                    return True, response.url, 'active'  # Return final URL after redirects
                else:
                    with self.logging_lock:
                        logging.info(f"Channel '{channel_name}': URL returned 200 but invalid M3U8 content")
                        logging.info(f"URL: {url}")
                        logging.info(f"SOURCE: {source_url}")
                        logging.info("")
                    return False, url, 'invalid_content'
            elif response.status_code == 403:
                with self.logging_lock:
                    logging.info(f"Channel '{channel_name}': ACTIVE - 403 Forbidden Geo-blocked HLS stream")
                    logging.info(f"URL: {url}")
                    logging.info(f"SOURCE: {source_url}")
                    logging.info("")
                return True, url, 'geo_blocked'
            else:
                content = response.text
                if response.status_code == 404 and 'Channel not available in current location' in content:
                    with self.logging_lock:
                        logging.info(f"Channel '{channel_name}': ACTIVE – 404 Forbidden Geo-blocked HLS stream")
                        logging.info(f"URL: {url}")
                        logging.info(f"SOURCE: {source_url}")
                        logging.info("")
                    return True, url, 'geo_blocked'
                
                # PATCH: Don't immediately fail on redirect service errors
                if self.is_redirect_service(url) and response.status_code in [530, 503, 502]:
                    with self.logging_lock:
                        logging.info(f"Channel '{channel_name}': Redirect service temporary error - marking as potentially active")
                        logging.info(f"URL: {url}")
                        logging.info(f"SOURCE: {source_url}")
                        logging.info("")
                    return True, url, 'redirect_service_error'
                
                with self.logging_lock:
                    logging.info(f"Channel '{channel_name}': HLS stream INACTIVE [ERROR_{response.status_code}]")
                    logging.info(f"URL: {url}")
                    logging.info(f"SOURCE: {source_url}")
                    logging.info("")
                return False, url, f'http_{response.status_code}'
                
        except requests.RequestException as e:
            logging.debug(f"Channel '{channel_name}': HLS validation failed - URL: {url} - Source: {source_url} - Error: {e}")
            # Fallback to regular URL validation
            return self.validate_regular_url(url, headers, timeout, channel_name, source_url)

    def validate_regular_url(self, url, headers, timeout, channel_name="Unknown Channel", source_url="Unknown Source"):
        """
        Validate regular URLs with ENHANCED redirect handling.
        
        Args:
            url (str): URL to validate
            headers (dict): Request headers
            timeout (int): Request timeout
            channel_name (str): Channel name for detailed logging
            source_url (str): Source URL for troubleshooting
            
        Returns:
            tuple: (is_active, final_url, status_info)
        """
        # PATCH: Enhanced redirect handling for redirect services
        if self.is_redirect_service(url):
            try:
                # For redirect services, use GET with full redirect following
                with requests.get(url, headers=headers, timeout=timeout, 
                                stream=True, allow_redirects=True) as response:
                    if response.status_code < 400:
                        with self.logging_lock:
                            logging.info(f"Channel '{channel_name}': ACTIVE (GET via redirect)")
                            logging.info(f"URL: {response.url}")  # Log final URL
                            logging.info(f"SOURCE: {source_url}")
                            logging.info("")
                        return True, response.url, 'active'
                    elif response.status_code == 403:
                        with self.logging_lock:
                            logging.info(f"Channel '{channel_name}': ACTIVE - 403 Forbidden Geo-blocked (GET via redirect)")
                            logging.info(f"URL: {response.url}")
                            logging.info(f"SOURCE: {source_url}")
                            logging.info("")
                        return True, response.url, 'geo_blocked'
                    # For redirect service errors, try with basic headers
                    elif response.status_code in [530, 503, 502]:
                        basic_headers = {'User-Agent': self.user_agent}
                        try:
                            with requests.get(url, headers=basic_headers, timeout=timeout,
                                            stream=True, allow_redirects=True) as retry_response:
                                if retry_response.status_code < 400:
                                    with self.logging_lock:
                                        logging.info(f"Channel '{channel_name}': ACTIVE (GET via redirect, retry)")
                                        logging.info(f"URL: {retry_response.url}")
                                        logging.info(f"SOURCE: {source_url}")
                                        logging.info("")
                                    return True, retry_response.url, 'active'
                        except:
                            pass  # Continue with original error handling
            except requests.RequestException:
                pass  # Continue with original logic
        
        # Try HEAD request first (faster)
        try:
            response = requests.head(url, headers=headers, timeout=timeout, allow_redirects=True)
            if response.status_code < 400:
                with self.logging_lock:
                    logging.info(f"Channel '{channel_name}': ACTIVE (HEAD)")
                    logging.info(f"URL: {url}")
                    logging.info(f"SOURCE: {source_url}")
                    logging.info("")
                return True, response.url, 'active'
            elif response.status_code == 403:
                with self.logging_lock:
                    logging.info(f"Channel '{channel_name}': ACTIVE - 403 Forbidden Geo-blocked (HEAD)")
                    logging.info(f"URL: {url}")
                    logging.info(f"SOURCE: {source_url}")
                    logging.info("")
                return True, url, 'geo_blocked'
        except requests.RequestException:
            pass

        # Try GET request as fallback
        try:
            with requests.get(url, headers=headers, timeout=timeout, stream=True) as response:
                if response.status_code < 400:
                    with self.logging_lock:
                        logging.info(f"Channel '{channel_name}': ACTIVE (GET)")
                        logging.info(f"URL: {url}")
                        logging.info(f"SOURCE: {source_url}")
                        logging.info("")
                    return True, response.url, 'active'
                elif response.status_code == 403:
                    with self.logging_lock:
                        logging.info(f"Channel '{channel_name}': ACTIVE - 403 Forbidden Geo-blocked (GET)")
                        logging.info(f"URL: {url}")
                        logging.info(f"SOURCE: {source_url}")
                        logging.info("")
                    return True, url, 'geo_blocked'
                else:
                    with self.logging_lock:
                        logging.info(f"Channel '{channel_name}': (GET) INACTIVE [ERROR_{response.status_code}]")
                        logging.info(f"URL: {url}")
                        logging.info(f"SOURCE: {source_url}")
                        logging.info("")
                    return False, url, f'http_{response.status_code}'
        except requests.RequestException as e:
            logging.debug(f"Channel '{channel_name}': Regular validation failed - URL: {url} - Source: {source_url} - Error: {e}")

        # Try protocol switching as last resort
        try:
            alt_url = url.replace('http://', 'https://') if url.startswith('http://') else url.replace('https://', 'http://')
            if alt_url != url:  # Only try if URL actually changed
                response = requests.head(alt_url, timeout=timeout, headers=headers, allow_redirects=True)
                if response.status_code < 400:
                    with self.logging_lock:
                        logging.info(f"Channel '{channel_name}': ACTIVE (HEAD, switched protocol)")
                        logging.info(f"URL: {alt_url}")
                        logging.info(f"SOURCE: {source_url}")
                        logging.info("")
                    return True, alt_url, 'active'
                elif response.status_code == 403:
                    with self.logging_lock:
                        logging.info(f"Channel '{channel_name}': ACTIVE - 403 Forbidden Geo-blocked (HEAD, switched protocol)")
                        logging.info(f"URL: {alt_url}")
                        logging.info(f"SOURCE: {source_url}")
                        logging.info("")
                    return True, alt_url, 'geo_blocked'
                else:
                    with self.logging_lock:
                        logging.info(f"Channel '{channel_name}': (HEAD, switched protocol) INACTIVE [ERROR_{response.status_code}]")
                        logging.info(f"URL: {alt_url}")
                        logging.info(f"SOURCE: {source_url}")
                        logging.info("")
                    return False, alt_url, f'http_{response.status_code}'
        except requests.RequestException:
            pass

        # Mark as completely inactive
        with self.logging_lock:
            logging.info(f"Channel '{channel_name}': All validation methods failed - INACTIVE [CONNECTION_FAILED]")
            logging.info(f"URL: {url}")
            logging.info(f"SOURCE: {source_url}")
            logging.info("")
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
        ENHANCED: Now works globally across all groups.
        """
        if not self.enable_deduplication:
            return

        logging.info("Starting GLOBAL channel deduplication process")

        # PATCH: Collect all channels from all groups
        all_channels = []
        for group_name, channels in self.channels.items():
            for channel in channels:
                channel['original_group'] = group_name  # Track original group
                all_channels.append(channel)

        original_count = len(all_channels)
        
        if original_count <= 1:
            return

        # PATCH: Perform global deduplication
        unique_channels = []
        duplicates = []

        for channel in all_channels:
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

        # PATCH: Redistribute channels back to their groups
        self.channels.clear()
        for channel in unique_channels:
            group = channel['original_group']
            del channel['original_group']  # Clean up temporary field
            self.channels[group].append(channel)

        self.duplicate_channels.extend(duplicates)
        final_count = len(unique_channels)
        removed_count = original_count - final_count

        if removed_count > 0:
            logging.info(f"GLOBAL deduplication complete: Removed {removed_count} duplicate channels across all groups")
    
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
    
    def fix_encoding_issues(self, text):
        """
        Fix common UTF-8 encoding issues where text is misinterpreted as Latin-1.
        
        Args:
            text (str): Text that may have encoding issues
            
        Returns:
            str: Text with encoding issues fixed
        """
        if not text:
            return text
        
        try:
            # Check if text contains the classic UTF-8 -> Latin-1 misinterpretation patterns
            if 'Ã©' in text or 'Ã¨' in text or 'Ã' in text:
                # Try to fix by encoding as Latin-1 then decoding as UTF-8
                fixed_text = text.encode('latin-1').decode('utf-8')
                return fixed_text
            else:
                # No encoding issues detected, return as-is
                return text
        except (UnicodeDecodeError, UnicodeEncodeError):
            # If fixing fails, return original text
            return text

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
            if line.startswith('#EXTINF:') or line.startswith('EXTINF:'):
                total_extinf_lines += 1
                
                try:
                    attributes = self.extract_extinf_attributes(line)
                    
                    logo = attributes.get('tvg-logo', self.default_logo)
                    if logo and not logo.startswith(('http://', 'https://')):
                        logo = self.default_logo
                    
                    # === GROUP EXTRACTION ===
                    group = "Uncategorized"
                    extracted_group = attributes.get('group-title', '').strip()
                    if extracted_group and not extracted_group.isspace():
                        group = extracted_group
                    
                    group_occurrences[group] += 1
                    
                    # NEW: Simple and efficient exclusion check with logging
                    if self.should_exclude_group(group, source_url):
                        current_channel = {}
                        continue
                    
                    # === CHANNEL NAME EXTRACTION ===
                    name = "Unnamed Channel"
                    comma_match = re.search(r',(.+)$', line)
                    if comma_match:
                        raw_name = comma_match.group(1).strip()
                        name = self.fix_encoding_issues(raw_name)
                    
                    quality, resolution = self.extract_quality_info(name)
                    language = self.detect_content_language(name)
                    
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
                if line.startswith(('http://', 'https://')):
                    clean_url = self.clean_and_validate_url(line)
                    if clean_url and clean_url not in self.seen_urls:
                        self.seen_urls.add(clean_url)
                        current_channel['url'] = clean_url
                        
                        current_channel['url_domain'] = urlparse(clean_url).netloc
                        current_channel['is_hls'] = clean_url.endswith('.m3u8') or 'hls' in clean_url.lower()
                        
                        self.channels[current_channel['group']].append(current_channel)
                        channel_count += 1
                        self.channels_processed += 1
                    else:
                        self.skipped_non_http_count += 1
                    
                    current_channel = {}
        
        logging.info(f"Parsing complete: {channel_count} channels added from {source_url}")
        logging.info(f"Total EXTINF lines processed: {total_extinf_lines}")
        logging.info(f"Skipped non-HTTP URLs: {self.skipped_non_http_count}")
        
        if parsing_errors:
            logging.info(f"Encountered {len(parsing_errors)} parsing errors")
            for error in parsing_errors[:5]:
                logging.info(f"Line {error['line_num']}: {error['error']}")
        
        logging.info("Group distribution:")
        for group, count in sorted(group_occurrences.items(), key=lambda x: x[1], reverse=True):
            logging.info(f"  - {group}: {count} channels")
        
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
        
        for attr_name, pattern in patterns.items():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                raw_value = match.group(1).strip()
                # PATCH: Decode HTML entities specifically for group-title to ensure correct exclusion matching.
                if attr_name == 'group-title':
                    attributes[attr_name] = html.unescape(raw_value)
                else:
                    attributes[attr_name] = raw_value
        
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
        
        url = url.strip()
        url = re.sub(r'\s+', '', url)
        
        if not url.startswith(('http://', 'https://')):
            return None
        
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return None
            
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
                    return len(self.quality_preferences)
            
            self.channels[group_name] = sorted(channels, key=quality_sort_key)
    
    def filter_active_channels(self):
        """
        Filter channels by checking URL availability with detailed validation logging and error breakdown.
        Uses concurrent processing for performance optimization
        """
        if not self.check_links:
            logging.info("Link validation disabled - skipping active channel filtering")
            return
        
        logging.info("Starting comprehensive link validation process")
        start_time = time.time()
        
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
        inactive_by_error = defaultdict(int)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {}
            for url, channels in url_to_channels.items():
                channel_name = channels[0][1]['name']
                source_url = channels[0][1]['source']
                future = executor.submit(self.check_link_active, url, channel_name, source_url)
                future_to_url[future] = url
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                completed += 1
                
                if completed % 10 == 0 or completed == total_urls:
                    progress = (completed / total_urls) * 100
                    elapsed = time.time() - start_time
                    logging.info(f"Validation progress: {progress:.1f}% ({completed}/{total_urls}) - {elapsed:.1f}s elapsed")
                
                try:
                    is_active, final_url, status = future.result()
                    validation_results[url] = (is_active, final_url, status)
                    
                    if is_active:
                        for group, channel in url_to_channels[url]:
                            if final_url != url:
                                channel['url'] = final_url
                                channel['original_url'] = url
                            
                            channel['validation_status'] = status
                            channel['validation_timestamp'] = datetime.now().isoformat()
                            
                            if status == 'geo_blocked':
                                if not channel['name'].endswith('[Geo-blocked]'):
                                    channel['name'] = f"{channel['name']} [Geo-blocked]"
                                geo_blocked_count += 1
                            
                            active_channels[group].append(channel)
                    
                    else:
                        inactive_by_error[status] += len(url_to_channels[url])
                
                except Exception as e:
                    logging.error(f"Validation error for {url}: {e}")
                    validation_results[url] = (False, url, f'error: {e}')
                    inactive_by_error['validation_error'] += len(url_to_channels[url])
        
        original_count = sum(len(ch) for ch in self.channels.values())
        self.channels = active_channels
        final_count = sum(len(ch) for ch in self.channels.values())
        
        elapsed_time = time.time() - start_time
        active_count = sum(1 for is_active, _, _ in validation_results.values() if is_active)
        
        logging.info(f"Link validation complete in {format_duration(int(elapsed_time))}")
        if total_urls > 0:
            logging.info(f"Results: {active_count}/{total_urls} URLs active ({(active_count/total_urls*100):.1f}%)")
        if original_count > 0:
            logging.info(f"Channels: {final_count}/{original_count} remaining ({(final_count/original_count*100):.1f}%)")
        logging.info(f"Active channels after filtering: {final_count}")
        logging.info(f"Geo-blocked channels detected: {geo_blocked_count}")
        
        if inactive_by_error:
            logging.info("INACTIVE channels breakdown by error type:")
            for error_type, count in sorted(inactive_by_error.items()):
                if error_type.startswith('http_'):
                    error_code = error_type.split('_')[1]
                    logging.info(f"  - HTTP {error_code} errors: {count} channels")
                else:
                    logging.info(f"  - {error_type}: {count} channels")
        
        self.statistics['urls_validated'] = total_urls
        self.statistics['active_urls'] = active_count
        self.statistics['geo_blocked_urls'] = geo_blocked_count
        self.statistics['validation_time'] = elapsed_time
        self.statistics['inactive_by_error'] = dict(inactive_by_error)
    
    def process_sources(self, source_urls):
        """
        Process all source URLs with comprehensive pipeline.
        
        Args:
            source_urls (list): List of source URLs to process
        """
        logging.info(f"Starting processing of {len(source_urls)} source URLs")
        self.start_time = time.time()
        
        self.channels.clear()
        self.seen_urls.clear()
        self.url_status_cache.clear()
        self.duplicate_channels.clear()
        self.failed_urls.clear()
        
        all_m3u_urls = set()
        
        for i, url in enumerate(source_urls, 1):
            logging.info(f"Processing source {i}/{len(source_urls)}: {url}")
            
            content, lines, metadata = self.fetch_content_with_retry(url)
            
            if not lines:
                logging.info(f"No content retrieved from {url}")
                continue
            
            if url.endswith('.html') or (metadata and metadata.get('content_type', '').startswith('text/html')):
                extracted_urls = self.extract_stream_urls_from_html(content, url)
                all_m3u_urls.update(extracted_urls)
                logging.info(f"Extracted {len(extracted_urls)} potential M3U URLs from HTML")
            else:
                self.test_cuisine_detection(lines)
                self.parse_and_store(lines, url, metadata)
        
        if all_m3u_urls:
            logging.info(f"Processing {len(all_m3u_urls)} extracted M3U URLs")
            for m3u_url in all_m3u_urls:
                content, lines, metadata = self.fetch_content_with_retry(m3u_url)
                if lines:
                    self.test_cuisine_detection(lines)
                    self.parse_and_store(lines, m3u_url, metadata)
        
        total_parsed = sum(len(ch) for ch in self.channels.values())
        logging.info(f"PHASE 1 COMPLETE: {total_parsed} channels parsed across {len(self.channels)} groups")
        
        important_groups = ['Cuisine', 'Actualités', 'Sports', 'Généraliste']
        for group in important_groups:
            if group in self.channels:
                count = len(self.channels[group])
                logging.info(f"{group} channels found: {count}")
        
        if total_parsed > 0:
            logging.info("Starting post-processing pipeline")
            
            self.deduplicate_channels()
            self.sort_channels_by_quality()
            
            if self.check_links:
                self.filter_active_channels()
            
            final_count = sum(len(ch) for ch in self.channels.values())
            processing_time = time.time() - self.start_time
            
            logging.info(f"Processing complete: {final_count} final channels in {format_duration(int(processing_time))}")
            logging.info(f"Groups: {', '.join(sorted(self.channels.keys()))}")
            
            # NEW: Log exclusion summary
            self.log_exclusion_summary()
            
            self.statistics['total_processing_time'] = processing_time
            self.statistics['final_channel_count'] = final_count
            self.statistics['source_urls_processed'] = len(source_urls)
    
    def export_m3u(self, filename="LiveTV.m3u"):
        """Export channels to standard M3U playlist format with enhanced metadata."""
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('#EXTM3U\n')
            f.write(f'#PLAYLIST:M3U Playlist for {self.country}\n')
            f.write(f'#EXTENC:UTF-8\n')
            f.write(f'#CREATED:{datetime.now().isoformat()}\n')
            f.write(f'#TOTAL-CHANNELS:{sum(len(ch) for ch in self.channels.values())}\n')
            f.write('\n')
            
            for group, channels in sorted(self.channels.items()):
                f.write(f'# --- {group} ({len(channels)} channels) ---\n')
                
                for channel in channels:
                    extinf_parts = ['#EXTINF:-1']
                    
                    if channel.get('logo'):
                        extinf_parts.append(f'tvg-logo="{channel["logo"]}"')
                    extinf_parts.append(f'group-title="{group}"')
                    
                    if channel.get('attributes'):
                        for attr, value in channel['attributes'].items():
                            if attr not in ['group-title', 'tvg-logo'] and value:
                                extinf_parts.append(f'{attr}="{value}"')
                    
                    if channel.get('resolution') and channel['resolution'] != 'Unknown':
                        extinf_parts.append(f'tvg-resolution="{channel["resolution"]}"')
                    
                    if channel.get('language') and channel['language'] != 'unknown':
                        extinf_parts.append(f'tvg-language="{channel["language"]}"')
                    
                    f.write(f'{" ".join(extinf_parts)},{channel["name"]}\n')
                    f.write(f'{channel["url"]}\n')
                
                f.write('\n')
        
        logging.info(f"Exported M3U playlist to {filepath}")
        return filepath
    
    def export_txt(self, filename="LiveTV.txt"):
        """Export channels to human-readable text format with detailed information."""
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"Live TV Channel List for {self.country}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Channels: {sum(len(ch) for ch in self.channels.values())}\n")
            f.write(f"Total Groups: {len(self.channels)}\n")
            f.write("=" * 80 + "\n\n")
            
            for group, channels in sorted(self.channels.items()):
                f.write(f"GROUP: {group} ({len(channels)} channels)\n")
                f.write("-" * 60 + "\n")
                
                for i, channel in enumerate(channels, 1):
                    f.write(f"{i:3d}. {channel['name']}\n")
                    f.write(f"     URL: {channel['url']}\n")
                    f.write(f"     Logo: {channel.get('logo', 'N/A')}\n")
                    f.write(f"     Source: {channel['source']}\n")
                    
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
        
        mumbai_tz = pytz.timezone('Asia/Kolkata')
        current_time = datetime.now(mumbai_tz).strftime('%Y-%m-%d %H:%M:%S')
        
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
            "failed_urls": self.failed_urls[:10],
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
    
    def export_all_formats(self):
        """Export channels to all supported formats"""
        exported_files = []
        
        export_methods = [
            ('M3U', self.export_m3u),
            ('TXT', self.export_txt),
            ('JSON', self.export_json),
            ('Custom', self.export_custom),
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
            
            f.write("PROCESSING STATISTICS\n")
            f.write("-" * 25 + "\n")
            for key, value in self.statistics.items():
                f.write(f"{key.replace('_', ' ').title()}: {value}\n")
            f.write("\n")
            
            f.write("CHANNEL DISTRIBUTION\n")
            f.write("-" * 20 + "\n")
            for group, channels in sorted(self.channels.items(), key=lambda x: len(x[1]), reverse=True):
                f.write(f"{group}: {len(channels)} channels\n")
            f.write("\n")
            
            if self.failed_urls:
                f.write("FAILED URLS\n")
                f.write("-" * 11 + "\n")
                for failed in self.failed_urls[:10]:
                    f.write(f"URL: {failed['url']}\n")
                    f.write(f"Error: {failed['error']}\n\n")
            
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
    Main execution function with comprehensive configuration and FIXED colored validation logging.
    """
    logging.info("Starting M3U Collector with full functionality")
    
    server_location = get_server_geolocation()
    
    excluded_groups = [
        # Original excluded groups
        "Argentina", "Austria", "Brazil", "Chile", "Denmark", "Germany",
        "India", "Italy", "Mexico", "Norway", "South Korea", "Spain",
        "Sweden", "Switzerland", "United Kingdom", "United States",
        "Offline", "Test", "Demo", "Shopping", "Teleshopping", "Business",
        "Culture", "Entertainmer", "Undefined", "Culture", "Religious",
        
        # Turkish groups from allgr.m3u
        "|TR|🇹🇷 AVRUPA; DİNÎ; DİĞER",
        "|TR|🇹🇷 BELGESEL & YAŞAM",
        "|TR|🇹🇷 ÇOCUK / SPOR",
        "|TR|🇹🇷 HABER",
        "|TR|🇹🇷 MÜZİK",
        "|TR|🇹🇷 ULUSAL GENEL",
        "|TR|🇹🇷 YEREL - BÖLGESEL",
        
        # Arabic groups from allgr.m3u
        "|AR|🇸🇦 MIDDLE EAST-1 عربي",
        "|AR|🇸🇦 MIDDLE EAST-2 عربي",
        "|AR|🇸🇦 THEMATICS-1 عربي",
        "|AR|🇸🇦 THEMATICS-2 عربي",
        
        # European groups from allgr.m3u
        "|DE|🇩🇪 DEUTSCHLAND - LOKALE",
        "|ES|🇪🇸 ESPAÑA",
        "|EU|🇪🇺 EUROPEAN COCKTAILTOUR🍸",
        "|GR|🇬🇷 GREECE Ελλά",
        "|HR-BA-RS++|🇭🇷🇧🇦🇷🇸 BALKANIC",
        "|IT|🇮🇹 ITALIA - LOCALE",
        "|PT|🇵🇹 PORTUGAL",
        
        # Middle Eastern & Regional groups from allgr.m3u
        "|GE-AM-AZ|🇬🇪🇦🇲🇦🇿 CAUCASIAN",
        "|IL|🇮🇱 ISRAEL ישראל",
        "|IR|🇮🇷 IRAN",
        "|LB|🇱🇧 LIBAN-LÜBNAN-LEBANON-لبنان",
        "|MA-DZ-TN|🇲🇦🇩🇿🇹🇳 MAGHREB المغرب",
        
        # International & Special groups from allgr.m3u
        "|EN-UK-US|🇬🇧🇺🇸 WORLDWIDE-INTL ℹ️🌐",
        "|📡|👨‍💻👉GITHUB.COM/IPSTREET312"
    ]
    
    source_urls = [
        "https://github.com/Sphinxroot/QC-TV/raw/16afc34391cf7a1dbc0b6a8273476a7d3f9ca33b/Quebec.m3u",
        "https://github.com/ipstreet312/freeiptv/raw/b16363ffa03752900de3fadb1d7fede7b7173901/ressources/allgr.m3u",
        "https://iptv-org.github.io/iptv/countries/ca.m3u",
        "https://tinyurl.com/Stream2IPTV?region=fr&service=PlutoTV",
        "https://tinyurl.com/Stream2IPTV?region=fr&service=SamsungTVPlus",
        "https://tinyurl.com/Stream2IPTV?region=fr&service=Plex",
        "https://raw.githubusercontent.com/iptv-org/iptv/master/streams/fr_rakuten.m3u",
        "https://list.iptvcat.com/my_list/33b417553a834a782ea5d4d15abbef92.m3u8",
    ]
    
    config = {
        'max_workers': 15,
        'request_timeout': 12,
        'max_retries': 2,
        'enable_deduplication': True,
        'enable_quality_sorting': True,
        'quality_preferences': ['4K', '1080p', '720p', '480p', '360p'],
        'language_preferences': ['fr', 'en']
    }
    
    collector = M3UCollector(
        country="Mikhoul",
        check_links=True,
        excluded_groups=excluded_groups,
        config=config
    )
    
    excluded_info = collector.get_excluded_groups_info()
    logging.info(f"Excluded groups: {excluded_info['excluded_count']} | {', '.join(excluded_groups[:5])}{'...' if len(excluded_groups) > 5 else ''}")
    
    try:
        collector.process_sources(source_urls)
        
        logging.info("Exporting to all supported formats")
        exported_files = collector.export_all_formats()
        
        collector.generate_report()
        
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
        
        if collector.channels:
            logging.info("Group summary:")
            for group in sorted(collector.channels.keys()):
                count = len(collector.channels[group])
                logging.info(f"  - {group}: {count} channels")
        
        if server_location:
            logging.info(f"Processing performed from: {server_location['country']} ({server_location['country_code']})")
    
    except Exception as e:
        logging.error(f"Critical error during processing: {e}")
        raise

if __name__ == "__main__":
    main()
