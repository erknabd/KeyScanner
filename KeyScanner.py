import argparse
import json
import os
import random
import re
import threading
import subprocess
from urllib.parse import urljoin

import requests


class CombinedApiKeyScanner:
    USER_AGENTS = [
        "Chrome/120.0.6099.200 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Safari/537.36",
        "Safari/605.1.15 (iPhone; CPU iPhone OS 16_4 like Mac OS X)",
        "Opera/98.0.4759.15 (Macintosh; Intel Mac OS X 13_2_1) Presto/2.12.388",
        "Brave/1.63.162 (Linux; Android 13; Pixel 7 Pro) Chrome/120.0.6099.201 Mobile",
        "Edge/121.0.2277.83 (Windows NT 11.0; Win64; x64)",
        "YaBrowser/23.9.3.765 (Linux; Android 12; Samsung Galaxy S22 Ultra) Chrome/119.0.6045.163 Mobile",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) rv:2025.09",
        "Safari/605.1.15 (Macintosh; Intel Mac OS X 14_0_1)",
        "Chrome/119.0.6045.105 (Linux; Android 11; Redmi Note 10 Pro) Mobile",
        "Opera/76.0.4017.123 (Windows NT 6.1; Win64; x64)",
        "Brave/1.62.153 (Macintosh; Intel Mac OS X 13_5_2) Chrome/119.0.6045.159",
        "Edge/120.0.2210.121 (iPad; CPU OS 17_1 like Mac OS X)",
        "YaBrowser/23.7.1.1000 (Windows NT 10.0; Win64; x64) Chrome/118.0.5993.117",
        "Mozilla/6.1 (Linux; Fedora; x86_64) Custom/2025.01",
    ]

    LANGUAGES = ["en-US,en;q=0.9", "tr-TR,tr;q=0.8,en-US;q=0.7"]

    REFERERS = [
        "https://google.com/", "https://bing.com/", "https://yahoo.com/", "https://duckduckgo.com/",
        "https://example.com/", "https://github.com/", "https://stackoverflow.com/", "https://reddit.com/",
        "https://twitter.com/", "https://facebook.com/", "https://linkedin.com/", "https://medium.com/",
        "https://cnn.com/", "https://bbc.com/", "https://nytimes.com/", "https://theverge.com/",
        "https://techcrunch.com/", "https://wikipedia.org/", "https://quora.com/", "https://instagram.com/",
        "https://youtube.com/", "https://pinterest.com/",
    ]

    def __init__(self, rotate_headers=True, timeout=10):
        self.google_api_dict = [
            (re.compile(r"https?://maps\.googleapis\.com/maps/api/staticmap[^\n\r]*[?&]key=([A-Za-z0-9\-_]{35})", re.IGNORECASE), ("Google Static Maps", "$2 / optional")),
            (re.compile(r"https?://maps\.googleapis\.com/maps/api/streetview[^\n\r]*[?&]key=([A-Za-z0-9\-_]{35})", re.IGNORECASE), ("Google Streetview", "$7 / image")),
            (re.compile(r"https?://www\.google\.com/maps/embed/v1/place[^\n\r]*[?&]key=([A-Za-z0-9\-_]{35})", re.IGNORECASE), ("Google Embed", "Varies")),
            (re.compile(r"https?://maps\.googleapis\.com/maps/api/directions/json[^\n\r]*[?&]key=([A-Za-z0-9\-_]{35})", re.IGNORECASE), ("Google Directions", "$5 / usage")),
            (re.compile(r"https?://maps\.googleapis\.com/maps/api/geocode/json[^\n\r]*[?&]key=([A-Za-z0-9\-_]{35})", re.IGNORECASE), ("Google Geocoding", "$5 / usage")),
            (re.compile(r"https?://maps\.googleapis\.com/maps/api/distancematrix/json[^\n\r]*[?&]key=([A-Za-z0-9\-_]{35})", re.IGNORECASE), ("Google Distance Matrix", "$5 / usage")),
            (re.compile(r"https?://maps\.googleapis\.com/maps/api/place/findplacefromtext/json[^\n\r]*[?&]key=([A-Za-z0-9\-_]{35})", re.IGNORECASE), ("Google FindPlaceFromText", "Varies")),
            (re.compile(r"https?://maps\.googleapis\.com/maps/api/place/autocomplete/json[^\n\r]*[?&]key=([A-Za-z0-9\-_]{35})", re.IGNORECASE), ("Google Autocomplete", "Varies")),
            (re.compile(r"https?://maps\.googleapis\.com/maps/api/elevation/json[^\n\r]*[?&]key=([A-Za-z0-9\-_]{35})", re.IGNORECASE), ("Google Elevation", "$5")),
            (re.compile(r"https?://maps\.googleapis\.com/maps/api/timezone/json[^\n\r]*[?&]key=([A-Za-z0-9\-_]{35})", re.IGNORECASE), ("Google Timezone", "$5")),
            (re.compile(r"https?://roads\.googleapis\.com/v1/nearestRoads[^\n\r]*[?&]key=([A-Za-z0-9\-_]{35})", re.IGNORECASE), ("Google Roads", "$10")),
            (re.compile(r"https?://www\.googleapis\.com/geolocation/v1/geolocate[^\n\r]*[?&]key=([A-Za-z0-9\-_]{35})", re.IGNORECASE), ("Google Geolocate", "Varies")),
        ]

        self.simple_patterns = [
            (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), ("AWS Access Key", "High", "Full AWS access usually requires an accompanying secret")),
            (re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b", re.IGNORECASE), ("Google API Key (AIza...)", "High", "Google API key candidate")),
            (re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b", re.IGNORECASE), ("Stripe Live Secret Key", "Critical", "Payments risk")),
            (re.compile(r"\b(sk_test_[0-9a-zA-Z]{24,})\b", re.IGNORECASE), ("Stripe Test Secret Key", "Medium", "Test key")),
            (re.compile(r"\b(ghp_[0-9A-Za-z]{36})\b", re.IGNORECASE), ("GitHub Personal Access Token (ghp_)", "High", "Repo access risk")),
            (re.compile(r"\b(xox[bosp]-[0-9A-Za-z-]{10,})\b", re.IGNORECASE), ("Slack Token (xox-)", "High", "Messaging/hook risk")),
            (re.compile(r"\b(AC[0-9a-fA-F]{32})\b"), ("Twilio Account SID candidate (AC...)", "High", "Often paired with auth token")),
            (re.compile(r"\b(sk-[0-9a-zA-Z]{48})\b"), ("OpenAI API Key", "High", "OpenAI API key candidate")),
            (re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), ("Mailgun API Key", "High", "Mailgun API key")),
            (re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"), ("MailChimp API Key", "High", "MailChimp API key")),
            (re.compile(r"\beyJ[A-Za-z0-9-_=]+?\.[A-Za-z0-9-_=]+(?:\.[A-Za-z0-9-_.+/=]*)?\b"), ("JWT Token", "High", "JWT-like token")),
            (re.compile(r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----"), ("RSA Private Key", "Critical", "RSA private key")),
            (re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----"), ("PGP Private Key", "Critical", "PGP private key")),
        ]

        self.context_patterns = [
            (re.compile(r"(?i)(?:aws_secret_access_key|aws_secret|secret_key|secret)[\s\"']{0,6}[:=]\s*[\'\"]?([A-Za-z0-9/+=]{40})[\'\"]?"), ("Possible AWS Secret-like (40)", "High", "Likely AWS-style 40-char secret")),
            (re.compile(r"(?i)(?:api[_-]?key|apikey|key|secret|token|client_secret|access_key)[\s\"']{0,6}[:=]\s*[\'\"]?([A-Za-z0-9/+=]{40})[\'\"]?"), ("Generic 40-char secret (contextual)", "High", "Assigned to key-like name")),
            (re.compile(r"(?i)(?:api[_-]?secret|secret|api[_-]?key|apikey|token)[\s\"']{0,6}[:=]\s*[\'\"]?([a-f0-9]{32})[\'\"]?"), ("Generic 32-hex (contextual)", "Medium", "32-hex secret assigned to key-like name")),
            (re.compile(r"(?i)[\"'](?:api[_-]?key|key|secret|token|client_secret|access_key)[\"']\s*:\s*[\"']([A-Za-z0-9/+=]{32,40})[\"']"), ("JSON-assigned secret (32-40)", "High", "Secret found in JSON field")),
            (re.compile(r"(?i)(?:data-[\w-]*key|data-[\w-]*secret|meta name=[\"'](?:api-key|client-secret|client-id)[\"'])[^>]*content=[\"']?([A-Za-z0-9\-_\/+=]{16,40})[\"']?"), ("HTML data/meta secret", "Medium", "data-attribute or meta content matched")),
        ]

        self.param_whitelist = set([
            "api", "key", "api_key", "apikey", "client_id", "client_secret", "access_key", "secret",
            "token", "auth", "auth_token", "aws_secret_access_key", "aws_access_key_id", "bearer",
            "jwt_token", "private_key", "secretKey", "secret_token", "oauth_token"
        ])

        self.url_param_pattern = re.compile(r"[?&]([^=&#\s]+)=([^&#\s]+)", flags=re.IGNORECASE)

        # rotate_headers: if True -> pick headers randomly per request
        # if False -> pick one static header per instance (more natural than a fixed literal)
        self.rotate_headers = rotate_headers
        self.static_headers = self._choose_static_headers() if not rotate_headers else None

        self.snippet_len = 160
        self.timeout = timeout

    def _choose_static_headers(self):
        return {
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept-Language": random.choice(self.LANGUAGES),
            "Referer": random.choice(self.REFERERS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

    def _random_headers(self):
        return {
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept-Language": random.choice(self.LANGUAGES),
            "Referer": random.choice(self.REFERERS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

    def _build_headers(self):
        if self.rotate_headers:
            return self._random_headers()
        return self.static_headers

    def parse_args(self):
        p = argparse.ArgumentParser(description="Critical Api Key & Secret Key Scanner")
        p.add_argument("-u", "--url", help="Single URL to scan")
        p.add_argument("-t", "--target", help="File with list of URLs (one per line)")
        p.add_argument("-o", "--output", help="Save results to JSON file (optional)")
        p.add_argument("--use-wayback", action="store_true", help="Also fetch URLs from Wayback CDX and scan them")
        p.add_argument("--fuzz", action="store_true", help="Run simple directory fuzzing (use with --wordlist)")
        p.add_argument("--wordlist", help="Wordlist file for fuzzing (one path per line)")
        p.add_argument("--threads", type=int, default=10, help="Threads for fuzzing (default 10)")
        p.add_argument("--external-waybackurls", action="store_true", help="If installed, run external waybackurls tool and include its output")
        p.add_argument("--external-ffuf", action="store_true", help="If installed, call ffuf for fuzzing (user must configure ffuf options externally)")
        p.add_argument("--external-gobuster", action="store_true", help="If installed, call gobuster for fuzzing (user must configure gobuster options externally)")
        return p.parse_args()

    def fetch_lines(self, url):
        if not url.startswith("http"):
            url = "http://" + url
        try:
            headers = self._build_headers()
            r = requests.get(url, timeout=self.timeout, headers=headers, allow_redirects=True)
            r.raise_for_status()
            return r.text.splitlines()
        except Exception as exc:
            print(f"[!] Could not fetch {url}: {exc}")
            return []

    def pretty_print(self, tag, title, key, extra, source_url, line_no, line):
        snippet = (line[: self.snippet_len] + "...") if len(line) > self.snippet_len else line
        print(f"[{tag}] {title} | Key: {key} | {extra}")
        print(f"    Source: {source_url} (line {line_no})")
        print(f"    Snippet: {snippet}")

    def fetch_wayback_urls(self, target):
        cdx_api = "http://web.archive.org/cdx/search/cdx"
        params = {"url": target, "output": "json", "fl": "original", "filter": "statuscode:200", "collapse": "original"}
        try:
            headers = self._build_headers()
            r = requests.get(cdx_api, params=params, headers=headers, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
            urls = []
            if isinstance(data, list) and len(data) > 1:
                for row in data[1:]:
                    if isinstance(row, list):
                        urls.append(row[0])
            return list(set(urls))
        except Exception as exc:
            print(f"[!] Wayback fetch failed for {target}: {exc}")
            return []

    def _fuzz_worker(self, base, queue, results, lock):
        while True:
            try:
                path = queue.pop()
            except IndexError:
                return
            full = urljoin(base, path.lstrip("/"))
            try:
                headers = self._build_headers()
                r = requests.get(full, timeout=self.timeout, headers=headers, allow_redirects=False)
                if r.status_code in (200, 301, 302, 401, 403, 500):
                    with lock:
                        results.append((full, r.status_code, len(r.content)))
                        print(f"[FUZZ] {full} -> {r.status_code} ({len(r.content)} bytes)")
            except Exception:
                pass

    def fuzz_paths(self, base_url, wordlist_path, threads=10):
        if not os.path.isfile(wordlist_path):
            print("[!] Wordlist not found:", wordlist_path)
            return []
        with open(wordlist_path, "r", errors="ignore") as f:
            words = [w.strip() for w in f if w.strip()]
        if not base_url.startswith("http"):
            base_url = "http://" + base_url
        queue = words[:]
        results = []
        lock = threading.Lock()
        workers = []
        for _ in range(min(threads, len(queue))):
            t = threading.Thread(target=self._fuzz_worker, args=(base_url, queue, results, lock))
            t.daemon = True
            t.start()
            workers.append(t)
        for t in workers:
            t.join()
        return results

    def call_external_waybackurls(self, target):
        try:
            p = subprocess.Popen(["waybackurls", target], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            out, _ = p.communicate(timeout=30)
            return [l.strip() for l in out.splitlines() if l.strip()]
        except Exception as exc:
            print(f"[!] External waybackurls failed: {exc}")
            return []

    def call_external_ffuf(self, base, wordlist, extra_args=None):
        extra_args = extra_args or []
        cmd = ["ffuf", "-u", f"{base}/FUZZ", "-w", wordlist] + extra_args
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, _ = p.communicate(timeout=120)
            print("[ffuf snippet]")
            print("\n".join(out.splitlines()[:20]))
            return out
        except Exception as exc:
            print(f"[!] ffuf call failed: {exc}")
            return ""

    def call_external_gobuster(self, base, wordlist, extra_args=None):
        extra_args = extra_args or []
        cmd = ["gobuster", "dir", "-u", base, "-w", wordlist] + extra_args
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, _ = p.communicate(timeout=120)
            print("[gobuster snippet]")
            print("\n".join(out.splitlines()[:20]))
            urls = []
            for line in out.splitlines():
                m = re.search(r"^/([\S]+)\s+\(\d+\)", line)
                if m:
                    urls.append(urljoin(base, m.group(1)))
            return urls
        except Exception as exc:
            print(f"[!] gobuster call failed: {exc}")
            return []

    def scan_url(self, url):
        results = []
        if not url.startswith("http"):
            url = "http://" + url
        try:
            headers = self._build_headers()
            r = requests.get(url, timeout=self.timeout, headers=headers, allow_redirects=True)
            content = r.text
        except Exception as exc:
            print(f"[!] Error fetching {url}: {exc}")
            return results

        lines = content.splitlines()

        # 1) URL parameter scanning
        for match in self.url_param_pattern.finditer(url):
            name, value = match.group(1), match.group(2)
            if name.lower() in (p.lower() for p in self.param_whitelist):
                results.append({
                    "type": "url_param",
                    "parameter": name,
                    "value": value,
                    "url": url,
                })
                print(f"[PARAM] Found parameter {name} in {url}")

        # 2) Simple token pattern search
        for idx, line in enumerate(lines, start=1):
            for pat, meta in self.simple_patterns:
                for m in pat.finditer(line):
                    key = m.group(1)
                    title, severity, extra = meta
                    self.pretty_print("SIMPLE", title, key, severity + " — " + extra, url, idx, line)
                    results.append({
                        "type": "simple",
                        "title": title,
                        "severity": severity,
                        "extra": extra,
                        "key": key,
                        "source_url": url,
                        "line_no": idx,
                        "snippet": (line[: self.snippet_len] + "...") if len(line) > self.snippet_len else line,
                    })

        # 3) Contextual patterns (JSON assignments, secrets near keywords)
        for idx, line in enumerate(lines, start=1):
            for pat, meta in self.context_patterns:
                m = pat.search(line)
                if m:
                    key = m.group(1)
                    title, severity, extra = meta
                    self.pretty_print("CONTEXT", title, key, severity + " — " + extra, url, idx, line)
                    results.append({
                        "type": "context",
                        "title": title,
                        "severity": severity,
                        "extra": extra,
                        "key": key,
                        "source_url": url,
                        "line_no": idx,
                        "snippet": (line[: self.snippet_len] + "...") if len(line) > self.snippet_len else line,
                    })

        # 4) Google-specific endpoint matches across the full content (sometimes in hrefs)
        for pat, meta in self.google_api_dict:
            for m in pat.finditer(content):
                key = m.group(1) if m.groups() else None
                title, extra = meta
                where = url
                self.pretty_print("GOOGLE", title, key, extra, where, 0, key or "")
                results.append({
                    "type": "google",
                    "title": title,
                    "extra": extra,
                    "key": key,
                    "source_url": where,
                })

        return results

    def scan_target_file(self, filepath, output=None, use_wayback=False, fuzz=False, wordlist=None, threads=10, external_wayback=False, external_ffuf=False, external_gobuster=False):
        all_results = []
        try:
            with open(filepath, "r") as f:
                urls = [l.strip() for l in f if l.strip()]
            for u in urls:
                r = self.scan_url(u)
                all_results.extend(r)

                if use_wayback:
                    print(f"[+] Fetching wayback URLs for {u} ...")
                    wb_urls = []
                    if external_wayback:
                        wb_urls += self.call_external_waybackurls(u)
                    wb_urls += self.fetch_wayback_urls(u)
                    wb_urls = list(set(wb_urls))
                    print(f"[+] {len(wb_urls)} wayback URLs found for {u}")
                    for w in wb_urls:
                        all_results.extend(self.scan_url(w))

                if fuzz and wordlist:
                    print(f"[+] Starting fuzzing on {u} with {wordlist} (threads={threads}) ...")
                    fuzz_res = self.fuzz_paths(u, wordlist, threads=threads)
                    if external_ffuf:
                        print("[+] Calling external ffuf ...")
                        self.call_external_ffuf(u, wordlist)
                    if external_gobuster:
                        print("[+] Calling external gobuster ...")
                        gob_urls = self.call_external_gobuster(u, wordlist)
                        for g in gob_urls:
                            fuzz_res.append((g, 200, 0))
                    for fr in fuzz_res:
                        full, code, size = fr
                        all_results.append({"type": "fuzz", "url": full, "status": code, "size": size})
        except FileNotFoundError:
            print("[!] Target file not found.")
        if output:
            with open(output, "w") as out:
                json.dump(all_results, out, indent=2)
        return all_results


def main():
    scanner = CombinedApiKeyScanner()
    args = scanner.parse_args()

    if args.url:
        results = scanner.scan_url(args.url)
        if args.output:
            with open(args.output, "w") as fh:
                json.dump(results, fh, indent=2)

    elif args.target:
        scanner.scan_target_file(
            args.target,
            output=args.output,
            use_wayback=args.use_wayback,
            fuzz=args.fuzz,
            wordlist=args.wordlist,
            threads=args.threads,
            external_wayback=args.external_waybackurls,
            external_ffuf=args.external_ffuf,
            external_gobuster=args.external_gobuster,
        )
    else:
        print("Usage: -u <url> OR -t <targets.txt> [-o out.json] [--use-wayback] [--fuzz --wordlist words.txt]")


if __name__ == "__main__":
    main()
