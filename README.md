# AutoXSS - Automated XSS Vulnerability Scanner

AutoXSS is an open-source tool designed for automatically scanning and detecting Cross-Site Scripting (XSS) vulnerabilities in web applications. It supports both reflected and DOM-based XSS attacks. 

## Features
- Scans for **Reflected XSS** vulnerabilities by injecting payloads into request parameters, headers, and cookies.
- Detects **DOM-based XSS** by analyzing JavaScript patterns in the response.
- Supports both **GET** and **POST** HTTP methods.
- Ability to load custom payloads from a file.
- Detailed report generation in **JSON** and **CSV** formats.
- Proxy support for scanning through a proxy server.

## Requirements
- Python 3.x
- Install the required dependencies using `pip`:

```bash
pip install requests beautifulsoup4
