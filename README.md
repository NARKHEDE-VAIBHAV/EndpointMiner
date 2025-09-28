
# EndpointMiner

Small, practical endpoint and API discovery tool (single-file Python script: `EndpointMiner.py`).

## Features
- Auto crawl starting URL with polite delays and robots.txt respect
- Manual mode: scan URL lists or HAR files
- Proxy capture via selenium-wire or mitmdump
- Heuristics for sensitive endpoints, JSON responses, and common secret patterns
- Outputs `findings.json`, `endpoints.txt`, and `secrets.txt` (if any)

## Quick install
```bash
python3 -m pip install --user requests beautifulsoup4
# optional extras:
python3 -m pip install --user selenium-wire selenium webdriver-manager mitmproxy pandas openpyxl
```

## Usage examples

Auto crawl:

```bash
python3 EndpointMiner.py --mode auto --start https://example.com --depth 2 --output findings.json
```

Manual from HAR or URL list:

```bash
python3 EndpointMiner.py --mode manual --capture captured.har --output findings.json
```

Proxy capture with browser (selenium-wire):

```bash
python3 EndpointMiner.py --mode proxy --start https://example.com --duration 30 --capture capture_urls.txt
```

Proxy capture with mitmdump:

```bash
python3 EndpointMiner.py --mode proxy-mitm --mitm-port 8080 --capture capture_urls.txt
# configure your browser to use 127.0.0.1:8080, browse/login, then press ENTER to stop capture
```

## Notes and safety

* Only run against targets you own or are authorized to test.
* The tool may find secrets. Treat discovered secrets as highly sensitive and do not commit them to source control.
* Consider adding a `--save-secrets` flag before writing secrets to disk.

## Output

* `findings.json` - JSON with findings
* `endpoints.txt` - newline separated endpoints
* `secrets.txt` - discovered secret matches (if any)

## License

Add a `LICENSE` file (for example, MIT) if you want to allow reuse.

