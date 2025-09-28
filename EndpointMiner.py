

import argparse, time, json, re, threading, subprocess, shutil, sys
from urllib.parse import urljoin, urlparse, urldefrag
from concurrent.futures import ThreadPoolExecutor
import requests
from bs4 import BeautifulSoup
import urllib.robotparser as robotparser
from pathlib import Path

# -------- Config --------
MAX_WORKERS = 6
REQUEST_TIMEOUT = 8
MIN_DELAY_PER_HOST = 0.35
USER_AGENT = "DeepEndpointFinder/1.0"
SENSITIVE_PATTERNS = [r"/api/", r"\.json($|\?)", r"\.php($|\?)", r"/admin", r"/config", r"/backup", r"/\.git", r"/wp-admin"]
SECRET_PATTERNS = {
    "AWS_AK": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Google_API": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Slack_Token": re.compile(r"xox[baprs]-[0-9A-Za-z]{10,}"),
    "Hex_Secret": re.compile(r"(?:secret|token|key)[\"'\s:=]{0,8}([0-9a-fA-F]{32,})"),
    "JWT": re.compile(r"eyJ[a-zA-Z0-9_\-]{5,}\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+")
}
# ------------------------

class Crawler:
    def __init__(self, session=None, base_domain=None, max_depth=3, allowed_hosts=None):
        self.session = session or requests.Session()
        self.base_domain = base_domain
        self.max_depth = max_depth
        self.visited = set()
        self.lock = threading.Lock()
        self.host_last_time = {}
        self.findings = []
        self.allowed_hosts = allowed_hosts if allowed_hosts else ({base_domain} if base_domain else None)
        self.robots = robotparser.RobotFileParser()
        if base_domain:
            for scheme in ("https://", "http://"):
                try:
                    self.robots.set_url(f"{scheme}{base_domain}/robots.txt")
                    self.robots.read()
                    break
                except Exception:
                    pass

    def polite_get(self, url):
        host = urlparse(url).netloc
        with self.lock:
            last = self.host_last_time.get(host, 0)
            wait = MIN_DELAY_PER_HOST - (time.time() - last)
            if wait > 0:
                time.sleep(wait)
            self.host_last_time[host] = time.time()
        headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/json,application/xhtml+xml,*/*"}
        try:
            return self.session.get(url, timeout=REQUEST_TIMEOUT, headers=headers, allow_redirects=True)
        except Exception:
            return None

    def normalize(self, base, link):
        if not link:
            return None
        url = urljoin(base, link)
        url, _ = urldefrag(url)
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return None
        return url

    def allowed(self, url):
        if not url: return False
        p = urlparse(url)
        host = p.netloc
        if self.allowed_hosts and host not in self.allowed_hosts:
            return False
        try:
            if hasattr(self.robots, "can_fetch"):
                if not self.robots.can_fetch(USER_AGENT, url):
                    return False
        except Exception:
            pass
        return True

    def extract_links(self, html, base_url):
        soup = BeautifulSoup(html, "html.parser")
        urls = set()
        for tag in soup.find_all(["a", "script", "link", "img", "form"]):
            attr = "href" if tag.name in ("a", "link") else ("src" if tag.name in ("script","img") else "action")
            link = tag.get(attr)
            n = self.normalize(base_url, link)
            if n: urls.add(n)
        for m in re.findall(r"(https?://[^\s'\"<>]+)", html):
            urls.add(urldefrag(m)[0])
        return urls

    def analyze_content(self, url, text, status_code, content_type):
        findings = []
        low = (url or "").lower()
        for p in SENSITIVE_PATTERNS:
            if re.search(p, low):
                findings.append({"type": "sensitive_pattern", "pattern": p, "url": url})
        for name, rx in SECRET_PATTERNS.items():
            for m in rx.findall(text or ""):
                val = m if isinstance(m, str) else (m[0] if m else "")
                if val:
                    findings.append({"type": "secret", "subtype": name, "match": val, "url": url})
        if "application/json" in (content_type or "") or (text or "").strip().startswith("{"):
            findings.append({"type": "json_response", "url": url})
        if status_code and status_code >= 400:
            findings.append({"type": "http_error", "status": status_code, "url": url})
        return findings

    def crawl_url(self, url, depth):
        if depth < 0: return []
        with self.lock:
            if url in self.visited: return []
            self.visited.add(url)
        if not self.allowed(url): return []
        resp = self.polite_get(url)
        if resp is None: return []
        ctype = resp.headers.get("Content-Type", "")
        try:
            text = resp.text if "text" in ctype or "html" in ctype or resp.encoding else resp.content.decode('utf-8', errors='ignore')
        except Exception:
            text = (resp.content.decode('utf-8', errors='ignore') if resp.content else "")
        local_findings = self.analyze_content(url, text, resp.status_code, ctype)
        with self.lock:
            self.findings.extend(local_findings)
        links = set()
        if "text/html" in ctype or "<html" in (text or "").lower():
            links = self.extract_links(text, url)
        return [(l, depth-1) for l in links if l]

    def run(self, seeds):
        to_visit = [(s, self.max_depth) for s in seeds if s and self.allowed(s)]
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = []
            while to_visit or futures:
                while to_visit and len(futures) < MAX_WORKERS*2:
                    link, depth = to_visit.pop(0)
                    futures.append(ex.submit(self.crawl_url, link, depth))
                done, notdone = [], []
                for f in futures:
                    if f.done():
                        done.append(f)
                    else:
                        notdone.append(f)
                futures = notdone
                for f in done:
                    try:
                        new = f.result()
                        for link, d in new:
                            p = urlparse(link)
                            if self.allowed_hosts and p.netloc not in self.allowed_hosts:
                                continue
                            with self.lock:
                                if link not in self.visited:
                                    to_visit.append((link, d))
                    except Exception:
                        pass
                if not futures and to_visit:
                    time.sleep(0.01)
        return self.findings

# ---------------- utilities ----------------
def load_capture_file(path):
    urls = []
    path = Path(path)
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8", errors="ignore")
    # try HAR detection
    if raw.lstrip().startswith("{") and '"log"' in raw:
        try:
            j = json.loads(raw)
            for e in j.get("log", {}).get("entries", []):
                req = e.get("request", {})
                url = req.get("url")
                if url: urls.append(url)
        except Exception:
            pass
    else:
        for line in raw.splitlines():
            line = line.strip()
            if line:
                urls.append(line)
    return list(dict.fromkeys(urls))

def parse_cookie_string(cookie_str):
    s = requests.Session()
    if not cookie_str:
        return s
    for p in [c.strip() for c in cookie_str.split(";") if "=" in c]:
        k,v = p.split("=",1)
        s.cookies.set(k.strip(), v.strip())
    return s

# ---------------- proxy capture (selenium-wire + webdriver-manager) ----------------
def capture_with_browser(start_url, duration=30, headless=True, capture_file="capture_urls.txt"):
    try:
        from seleniumwire import webdriver as sw_webdriver
        from selenium.webdriver.chrome.options import Options as ChromeOptions
        from selenium.webdriver.chrome.service import Service
        from webdriver_manager.chrome import ChromeDriverManager
    except Exception as e:
        raise RuntimeError(
            "Missing dependencies for selenium proxy mode. Install with:\n"
            "  python3 -m pip install --user selenium-wire selenium webdriver-manager"
        ) from e

    chrome_opts = ChromeOptions()
    chrome_opts.add_argument("--disable-gpu")
    chrome_opts.add_argument("--no-sandbox")
    chrome_opts.add_argument("--disable-dev-shm-usage")
    chrome_opts.add_argument("--ignore-certificate-errors")
    chrome_opts.add_argument("--allow-insecure-localhost")
    if headless:
        try:
            chrome_opts.add_argument("--headless=new")
        except Exception:
            chrome_opts.add_argument("--headless")
    seleniumwire_opts = {}

    service = Service(ChromeDriverManager().install())
    driver = sw_webdriver.Chrome(service=service, seleniumwire_options=seleniumwire_opts, options=chrome_opts)
    try:
        driver.get(start_url)
        t0 = time.time()
        print(f"[+] Browser opened. Capture for {duration}s. Headless={headless}")
        while time.time() - t0 < duration:
            time.sleep(0.5)
        urls = []
        for req in driver.requests:
            try:
                if getattr(req, "url", None):
                    urls.append(req.url)
            except Exception:
                pass
        urls = [u for u in dict.fromkeys(urls) if u]
        Path(capture_file).write_text("\n".join(urls), encoding="utf-8")
        print(f"[+] Captured {len(urls)} requests -> {capture_file}")
        return urls
    finally:
        try:
            driver.quit()
        except Exception:
            pass

# ---------------- proxy-mitm (mitmdump) ----------------
def start_mitmdump_capture(capture_file="capture_urls.txt", port=8080, mitm_script_path="mitm_log_urls.py"):
    mitmdump_bin = shutil.which("mitmdump")
    if not mitmdump_bin:
        raise RuntimeError("mitmdump not found. Install mitmproxy: python3 -m pip install --user mitmproxy or use your package manager.")
    # write small mitm script that appends request URLs
    mitm_py = f"""from mitmproxy import http
from pathlib import Path
OUT = {repr(capture_file)}
def request(flow: http.HTTPFlow) -> None:
    try:
        url = flow.request.pretty_url
        Path(OUT).write_text((Path(OUT).read_text() + url + "\\n") if Path(OUT).exists() else url + "\\n", encoding="utf-8")
    except Exception:
        pass
"""
    Path(mitm_script_path).write_text(mitm_py, encoding="utf-8")
    # ensure empty capture file
    Path(capture_file).write_text("", encoding="utf-8")
    proc = subprocess.Popen([mitmdump_bin, "-p", str(port), "-s", mitm_script_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.4)
    return proc

def stop_mitmdump_capture(proc):
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

# ---------------- CLI ----------------
def main():
    ap = argparse.ArgumentParser(description="Deep endpoint & API finder (auto/manual/proxy/proxy-mitm).")
    ap.add_argument("--mode", choices=("auto","manual","proxy","proxy-mitm"), required=True)
    ap.add_argument("--start", help="start URL for auto/proxy modes (e.g. https://example.com)")
    ap.add_argument("--capture", help="capture file (manual mode) or output file for proxy mode", default="capture_urls.txt")
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--cookie")
    ap.add_argument("--allowed-hosts")
    ap.add_argument("--output", default="findings.json")
    ap.add_argument("--duration", type=int, default=30, help="proxy mode capture duration in seconds")
    ap.add_argument("--headless", type=lambda s: s.lower()=="true", default=True, help="proxy mode headless true/false")
    ap.add_argument("--mitm-port", type=int, default=8080, help="port for mitmdump (proxy-mitm mode)")
    args = ap.parse_args()

    session = parse_cookie_string(args.cookie)
    session.headers.update({"User-Agent": USER_AGENT})
    allowed_hosts = None
    if args.allowed_hosts:
        allowed_hosts = set(h.strip() for h in args.allowed_hosts.split(",") if h.strip())

    seeds = []
    base_domain = None

    if args.mode == "auto":
        if not args.start:
            print("Auto mode requires --start URL"); return
        seeds = [args.start]
        base_domain = urlparse(args.start).netloc
        if not allowed_hosts:
            allowed_hosts = {base_domain}

    elif args.mode == "manual":
        if not args.capture:
            print("Manual mode requires --capture file path"); return
        seeds = load_capture_file(args.capture)
        if not allowed_hosts:
            allowed_hosts = set(urlparse(u).netloc for u in seeds if u)

    elif args.mode == "proxy":
        if not args.start:
            print("Proxy mode requires --start URL"); return
        capture_file = args.capture or "capture_urls.txt"
        print(f"[+] Launching browser to capture traffic for {args.duration}s (headless={args.headless}) ...")
        try:
            captured = capture_with_browser(args.start, duration=args.duration, headless=args.headless, capture_file=capture_file)
        except Exception as e:
            print("[-] Failed to start selenium proxy capture:", e)
            return
        seeds = captured
        if not allowed_hosts:
            allowed_hosts = set(urlparse(u).netloc for u in seeds if u)
        base_domain = urlparse(args.start).netloc

    else:  # proxy-mitm
        capture_file = args.capture or "capture_urls.txt"
        print(f"[+] Starting mitmdump on 127.0.0.1:{args.mitm_port}. Configure your browser (FoxyProxy) to use this proxy and browse/login.")
        try:
            proc = start_mitmdump_capture(capture_file=capture_file, port=args.mitm_port)
        except Exception as e:
            print("[-] Failed to start mitmdump:", e)
            return
        print("[+] mitmdump started. Browse the site now (login if needed). Press ENTER here when finished capture.")
        try:
            input()
        except KeyboardInterrupt:
            pass
        stop_mitmdump_capture(proc)
        # dedupe captured urls
        if Path(capture_file).exists():
            lines = []
            for line in Path(capture_file).read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line:
                    # extract urls from line if noise
                    m = re.findall(r"https?://[^\s'\"<>]+", line)
                    for u in m:
                        lines.append(u)
            uniq = list(dict.fromkeys(lines))
            Path(capture_file).write_text("\n".join(uniq), encoding="utf-8")
            print(f"[+] Captured {len(uniq)} unique URLs -> {capture_file}")
            seeds = uniq
            if not allowed_hosts:
                allowed_hosts = set(urlparse(u).netloc for u in seeds if u)
            # set base_domain if start provided
            base_domain = urlparse(args.start).netloc if args.start else None
        else:
            print("[-] No capture file created; aborting.")
            return

    crawler = Crawler(session=session, base_domain=base_domain, max_depth=args.depth, allowed_hosts=allowed_hosts)
    print(f"[+] Mode: {args.mode} | seeds: {len(seeds)} | max_depth: {args.depth} | allowed: {allowed_hosts}")
    findings = crawler.run(seeds)

    uniq = []
    seen = set()
    for f in findings:
        key = json.dumps(f, sort_keys=True)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    Path(args.output).write_text(json.dumps({"seeds": seeds, "findings": uniq}, indent=2, ensure_ascii=False))
    print(f"[+] Saved {len(uniq)} findings to {args.output}")
    counts = {}
    for f in uniq:
        counts[f.get("type")] = counts.get(f.get("type"),0)+1
    for t,c in counts.items():
        print(f"  - {t}: {c}")
    endpoints = "\n".join(sorted({f.get("url") for f in uniq if f.get("url")}))
    Path("endpoints.txt").write_text(endpoints, encoding="utf-8")
    secrets = "\n".join(sorted({(f.get("subtype") + " : " + f.get("match") + " -> " + f.get("url")) for f in uniq if f.get("type")=="secret"}))
    if secrets:
        Path("secrets.txt").write_text(secrets, encoding="utf-8")
    print("[+] Wrote endpoints.txt and secrets.txt (if any).")

if __name__ == "__main__":
    main()