# Automated Web Security Scanner

**Author:** Aditya Pathak  
**Project type:** Defensive cybersecurity / passive web configuration audit

## Description
A lightweight Python tool that makes a normal HTTP GET request and reports:
- Whether the final URL uses HTTPS and whether redirects occurred
- Presence and values of six common HTTP security headers
- Basic observations about `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`
- Optional JSON output for keeping a scan record

This is a passive configuration checker, not a penetration-testing tool. Missing headers are not proof of a vulnerability; findings require context and manual validation.

## Technologies
- Python 3.10 or later
- `requests` for HTTP requests
- Jupyter Notebook (optional, for the notebook version)
- Python standard library: `argparse`, `json`, `urllib.parse`, `datetime`

## Files
- `Aditya_Automated_Web_Security_Scanner.ipynb` — notebook version with explanation and runnable cells
- `Aditya_Automated_Web_Security_Scanner.py` — command-line version
- `requirements.txt` — Python dependency list
- `Aditya_ProjectReport.docx` — project report

## Setup
1. Install Python 3.10+.
2. (Optional but recommended) create and activate a virtual environment.
3. Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Run the Python script
Scan only a site you own or have explicit permission to assess:

```bash
python Aditya_Automated_Web_Security_Scanner.py https://example.com
```

Save a JSON report:

```bash
python Aditya_Automated_Web_Security_Scanner.py https://example.com --json scan_report.json
```

Set a custom timeout:

```bash
python Aditya_Automated_Web_Security_Scanner.py https://example.com --timeout 10
```

## Run the notebook
Open `Aditya_Automated_Web_Security_Scanner.ipynb` in Jupyter Notebook or VS Code, install requirements, and run the cells from top to bottom. The example target is `https://example.com`; replace it with an authorized target if needed.

## Dataset / data source
No dataset is required. The program analyzes HTTP response headers returned by the selected target URL at runtime. For safe practice, use a site you own or a deliberately configured local test server.

## Method
1. Normalize and validate the URL.
2. Send one GET request with a timeout and redirects enabled.
3. Inspect HTTPS status, redirect behavior, selected security headers, and basic CORS headers.
4. Display observations and optionally serialize them as JSON.

## Limitations
- One ordinary GET request only; no crawling, fuzzing, brute force, or exploitation.
- Header presence does not establish whether a configuration is secure in every context.
- CORS must be evaluated with the requesting origin and application behavior.
- Results can vary by URL, route, and response status.

## Responsible use
Use only against systems you own or are explicitly authorized to assess. Follow your institution's rules and applicable law.
