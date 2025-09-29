
````markdown
## KeyScanner

**Compact scanner to find exposed API keys, tokens and secrets in web pages**

A small Python utility that fetches web pages (or a list of targets) and searches for likely secrets (API keys, tokens, private keys, Google Maps keys, JWT-like tokens, etc.). It can optionally fetch Wayback snapshots and perform simple directory fuzzing using a wordlist. The script also supports calling a few external tools when installed (`waybackurls`, `ffuf`, `gobuster`).

> **Warning / Ethics**: This tool is intended for **authorized** security testing, auditing your own assets, or with explicit permission. Do **not** scan targets you do not own or don’t have written permission to test.

## Features

- Detects common token patterns (OpenAI, Google API, AWS keys, Stripe keys, GitHub PATs, Slack tokens, JWTs, RSA/PGP private keys, etc.).
- Context-aware pattern matching for JSON-style secret assignments.
- Google Maps / Google API-specific endpoint detection.
- Optional Wayback CDX integration to scan archived versions.
- Simple directory fuzzing (multi-threaded) using a local wordlist.
- Optional wrappers for external tools (`waybackurls`, `ffuf`, `gobuster`).

## Prerequisites

- Python 3.8+
- `pip` to install the dependency below

Optional external tools (if you want their extra features):
- `waybackurls` — https://github.com/tomnomnom/waybackurls
- `ffuf` — https://github.com/ffuf/ffuf
- `gobuster` — https://github.com/OJ/gobuster


## Installation

1. Clone repository (or place KeyScanner.py in a folder)

```bash
git clone https://github.com/erknabd/KeyScanner.git
cd gorilla
```

2. Install the Python dependency:

```bash
pip install -r requirements.txt
```

3. (Optional) Install external tools if you want Wayback or fuzzer integration.

## Usage

Basic single-URL scan:

```bash
python KeyScanner.py -u https://example.com
```

Scan a list of targets from a file and save JSON output:

```bash
python KeyScanner.py -t targets.txt -o results.json
```

Use Wayback snapshots when scanning a targets file:

```bash
python KeyScanner.py -t targets.txt --use-wayback -o results.json
```

Run basic fuzzing while scanning (requires a local wordlist):

```bash
python KeyScanner.py -t targets.txt --fuzz --wordlist wordlist.txt --threads 20
```

Enable external helpers (assumes the binaries are installed and on PATH):

```bash
python KeyScanner.py -t targets.txt --use-wayback --external-waybackurls --external-ffuf --external-gobuster
```

## Output

* By default results are printed to stdout. Use `-o results.json` to save a JSON array of findings.
* Fuzzing results are stored alongside other findings with the `type` field set to `fuzz`.

## Configuration notes

* The script randomizes request headers by default (to appear less repetitive); you can set `rotate_headers=False` in the `CombinedApiKeyScanner()` constructor if you prefer a single static header set.
* `timeout` and `snippet_len` can also be tweaked in the class constructor to tune performance and snippet size.

## Extending / Contributing

* Add or improve regex patterns in `simple_patterns`, `context_patterns`, or `google_api_dict` to catch more token shapes or vendor-specific formats.
* Improve rate-limiting/backoff and polite crawling (robots, fewer concurrent requests) for safer scans.
* Add tests for each pattern to reduce false positives.

## License

This repository is provided under the MIT License. Use responsibly.

```
```
