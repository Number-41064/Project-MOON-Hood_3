# Project MOON - Hood_3 🌐

An Automated Web Security Header & Sensitive File Scanner CLI tool built with Python.

## Features
- **Security Headers Check**: Scans for essential protective HTTP headers (CSP, HSTS, X-Frame-Options, etc.).
- **Sensitive Asset Detection**: Probes common web paths (`.env`, `.git/HEAD`, `phpinfo.php`, `robots.txt`) for potential data leaks.
- **Server Information Disclosure**: Extracts Server header data if exposed.

## Requirements
```bash
pip install -r requirements.txt