# Ingram - Network Camera Vulnerability Scanner

A fast, modular vulnerability scanning framework for network cameras (IP cameras, NVRs, DVRs). Supports 20+ device brands with 30+ exploits including CVE-based attacks, weak credential testing, authentication bypass, and RTSP stream detection.

> Private fork of [jorhelp/Ingram](https://github.com/jorhelp/Ingram) with significant enhancements.

---

## What's Changed From the Original

This is a private fork of [jorhelp/Ingram](https://github.com/jorhelp/Ingram). Below is a side-by-side comparison of what the original had versus what this version adds or changes.

### Console Interface

| | Original | This Fork |
|---|----------|-----------|
| **Status display** | Single-line text with a spinning icon: `[⣾] 50/1000(5.0%) Found 2 Time: 1m 0s/20m 0s` | Multi-line boxed dashboard with box-drawing borders, updates every 0.2s |
| **Progress** | Percentage number only | Visual progress bar with color gradient (red → yellow → green) + percentage |
| **Scan rate** | Not shown | Live targets/sec calculated from rolling sample window |
| **Time estimates** | Linear extrapolation from done/total | ETA based on actual measured throughput |
| **Per-target timing** | Not tracked | Shows current IP scan time, average per target, and last target time |
| **Vulnerability feed** | Not shown during scan; only final report | Real-time RECENT FINDINGS feed — last 3 discoveries shown live with IP, port, device, creds, POC name |
| **Device breakdown** | Only in final report | Live mini bar chart during scan showing vulnerability count per device brand |
| **Clickable targets** | No | Vulnerable IPs are OSC 8 terminal hyperlinks — Ctrl+Click to open in browser (Windows Terminal, VS Code) |
| **Current target** | Not shown | Shows which IP is actively being scanned |
| **Resume handling** | Silent — just resumes if state file exists, no indication | Interactive prompt: shows previous progress (targets done, vulns found, time elapsed), asks `[R] Resume / [F] Start Fresh`. Dashboard shows `[RESUMED]` tag |
| **Final report** | Plain text with basic bar chart | Boxed report matching dashboard style with per-device breakdown bars |
| **Language** | Chinese README and comments | English README and all user-facing text |

### Anti-Detection & Evasion

The original had **no evasion capabilities** — it scanned sequentially at full speed with a single static User-Agent, making it trivially detectable and blockable.

| Feature | Original | This Fork |
|---------|----------|-----------|
| **Scan speed control** | None — always max speed | Three profiles via `-S`: `stealth` (1-3s delay, 20 threads), `normal` (no delay, 150 threads), `aggressive` (no delay, 300 threads) |
| **User-Agent** | One static UA for the entire scan | Randomized per request from a pool of real browser UAs |
| **HTTP headers** | Static defaults | Randomized Accept-Language, DNT, Sec-Fetch-*, Connection headers per request |
| **Request rate** | No throttling | Configurable per-target rate limiting with jitter (`--delay`) |
| **Target order** | Sequential (scans IPs in file order) | Shuffled in chunks of 10,000 to avoid sequential detection (`--randomize`, on by default) |
| **Proxy support** | None | HTTP/SOCKS4/SOCKS5 via `--proxy`, or rotating proxy list via `--proxy-file` |
| **Retry logic** | No retries on failure | Exponential backoff with configurable retry count (`--retries`, default: 2) |

### Device & Vulnerability Coverage

The original supported **17 device brands** with **26 POCs** and CVEs from 2017-2021.

This fork adds **6 new device brands** and **4 new CVE exploits**, bringing totals to **23 brands** and **36+ POCs** with CVEs through 2023.

**New device brands added:**

| Brand | Original | This Fork |
|-------|----------|-----------|
| Reolink | Not supported | Fingerprint rules + JSON API weak password POC |
| Amcrest | Not supported | Fingerprint rules + HTTP Digest weak password + unauthenticated info disclosure POC |
| Lorex | Not supported | Fingerprint rules + RPC2_Login weak password POC |
| Honeywell | Not supported | Fingerprint rules + ISAPI weak password POC |
| Foscam | Not supported | Fingerprint rules + CGIProxy weak password POC |
| TP-Link | Not supported | Fingerprint rules added |

**New CVE exploits added:**

| CVE | Target | CVSS | Original | This Fork |
|-----|--------|------|----------|-----------|
| CVE-2022-30563 | Dahua | 7.4 | Not covered | ONVIF authentication bypass via WS-UsernameToken replay |
| CVE-2023-6895 | Hikvision/DVR | 9.8 | Not covered | Command injection via `restore` endpoint |
| CVE-2023-28808 | Hikvision | 9.1 | Not covered | Access control authentication bypass |
| Amcrest Disclosure | Amcrest | Medium | Not covered | Unauthenticated config leak via `/web_caps/webCapsConfig` |

**Credential & port expansion:**

| | Original | This Fork |
|---|----------|-----------|
| **Passwords** | 6 generic (`admin`, `12345`, etc.) | 19 total — added brand-specific: `888888`, `666666`, `000000`, blank password, `supervisor`, `admin123`, `default`, `pass` |
| **Ports scanned** | ~15 HTTP ports | 29 ports — added HTTPS (443, 8443), RTSP (554, 8554), device-specific (34567, 37777, 49152, 55555, 8888) |
| **Comment support** | No | Lines starting with `#` are ignored in target files and `rules.csv` |

### RTSP Stream Detection

The original had **no RTSP support** — it only tested HTTP-based vulnerabilities.

This fork adds:
- RTSP probing on ports 554 and 8554
- Default credential testing against RTSP endpoints
- Brand-specific RTSP path detection (Hikvision `/Streaming/Channels/101`, Dahua `/cam/realmonitor`, Reolink, Foscam, etc.)
- Disable with `--disable-rtsp`

### Output & Reporting

| | Original | This Fork |
|---|----------|-----------|
| **CSV** | `results.csv` with vulnerability results | Same, unchanged |
| **JSON** | Not available | `results.json` with structured scan metadata (`--output-format json`) |
| **HTML** | Not available | Dark-themed `report.html` with stat cards, severity badges, sortable tables (`--output-format html`) |
| **Format selection** | CSV only | `--output-format`: `csv`, `json`, `html`, or `all` |

### Target Discovery

The original required you to **manually create target files**. This fork adds:
- **Shodan integration** — pull camera IPs directly via `--shodan-key` and `--shodan-query`
- **Censys integration** — pull targets via `--censys-id`, `--censys-secret`, and `--censys-query`
- API results are automatically appended to the input target file

### Platform & Compatibility

| | Original | This Fork |
|---|----------|-----------|
| **Windows** | Partial — some features broken | Fully supported — colorama wrapping, UTF-8 stdout, VT100 escape activation |
| **Python 3.11+** | Broken (pwntools dependency) | Compatible — pwntools made optional |
| **README language** | Chinese | English |

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

---

## Supported Devices

| Brand | POC Types |
|-------|-----------|
| **Hikvision** | Weak password, CVE-2017-7921, CVE-2021-36260, CVE-2023-6895, CVE-2023-28808 |
| **Dahua** | Weak password, CVE-2021-33044, CVE-2021-33045, CVE-2022-30563, Disabled auth |
| **Uniview** | Credential disclosure, CVE-2021-36260 variant |
| **Xiongmai** | Weak password, ONVIF bypass |
| **Reolink** | Weak password |
| **Amcrest** | Weak password, Info disclosure |
| **Lorex** | Weak password |
| **Honeywell** | Weak password |
| **Foscam** | Weak password |
| **D-Link DCS** | CVE-2020-25078 |
| **Avtech** | Weak password |
| **Axis** | Weak password |
| **GeoVision** | Weak password |
| **Instar** | Weak password |
| **Netwave** | Weak password |
| **Nuuo** | Weak password |
| **ReeCam** | Weak password |
| **Tenda** | CVE-2018-17240 |
| **Generic DVR** | Weak password, CVE-2018-9995 |
| **Generic RTSP** | Default credential testing |

## Features

- **30+ vulnerability POCs** including CVEs from 2017-2023
- **Anti-detection system** — rate limiting, proxy rotation, User-Agent rotation, target randomization, stealth scanning mode
- **RTSP stream detection** — probe port 554/8554 for accessible camera streams
- **Multiple output formats** — CSV, JSON, and HTML reports
- **High concurrency** — gevent-based async scanning with configurable worker count
- **Resume capability** — interrupted scans can be continued from where they left off
- **Snapshot capture** — automatically captures images from vulnerable cameras
- **Proxy support** — HTTP/SOCKS4/SOCKS5 proxy and proxy list rotation
- **Shodan/Censys integration** — pull targets from internet search engines

## Installation

**Requirements:** Python >= 3.8 (3.11+ supported). Works on Linux, Mac, and Windows.

```bash
# Clone the repository
git clone https://github.com/WhenitComestoCodeIamNot/Ingram-scanner.git
cd Ingram-scanner

# Create and activate virtual environment
python -m venv venv
# Linux/Mac:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Scan

Prepare a target file (e.g., `targets.txt`) with IPs, one per line:

```
# Comments start with #

# Single IP
192.168.0.1

# IP with specific port
192.168.0.2:80

# CIDR notation
192.168.0.0/24

# IP range
192.168.0.0-192.168.0.255
```

Run the scanner:

```bash
python run_ingram.py -i targets.txt -o output_dir
```

### Scan Speed Profiles

```bash
# Stealth mode — slow, randomized, hard to detect
python run_ingram.py -i targets.txt -o output -S stealth

# Normal mode (default) — balanced speed and stealth
python run_ingram.py -i targets.txt -o output -S normal

# Aggressive mode — maximum speed, no delays
python run_ingram.py -i targets.txt -o output -S aggressive
```

### Using Proxies

```bash
# Single proxy
python run_ingram.py -i targets.txt -o output --proxy socks5://127.0.0.1:1080

# Rotating proxy list
python run_ingram.py -i targets.txt -o output --proxy-file proxies.txt
```

### Custom Ports and Threads

```bash
# Scan specific ports
python run_ingram.py -i targets.txt -o output -p 80 8080 8000

# Adjust concurrency (default: 150)
python run_ingram.py -i targets.txt -o output -t 500
```

### Output Formats

```bash
# JSON output
python run_ingram.py -i targets.txt -o output --output-format json

# HTML report
python run_ingram.py -i targets.txt -o output --output-format html

# All formats
python run_ingram.py -i targets.txt -o output --output-format all
```

### All Arguments

```
required arguments:
  -i, --in_file           Target file (IPs/ranges, one per line)
  -o, --out_dir           Output directory for results

scanning options:
  -p, --ports             Port(s) to scan (default: common camera ports)
  -t, --th_num            Worker/coroutine count (default: 150)
  -T, --timeout           Request timeout in seconds (default: 3)
  --retries               Max retries per request (default: 2)

evasion options:
  -S, --scan-speed        Scan profile: stealth, normal, aggressive (default: normal)
  --proxy                 Proxy URL (http/socks4/socks5)
  --proxy-file            File with proxy list (one per line, rotated)
  --delay                 Min delay between requests per target (seconds)
  --randomize             Shuffle target order (default: on)
  --no-randomize          Scan targets in sequential order

output options:
  --output-format         Output format: csv, json, html, all (default: csv)
  -D, --disable_snapshot  Skip snapshot capture
  --disable-rtsp          Skip RTSP stream detection

target sources:
  --shodan-key            Shodan API key
  --shodan-query          Shodan search query
  --censys-id             Censys API ID
  --censys-secret         Censys API secret
  --censys-query          Censys search query

other:
  --debug                 Enable debug logging
  -h, --help              Show help message
```

## Output Structure

```
output_dir/
├── results.csv           # Vulnerable devices: ip,port,device,user,password,vulnerability
├── results.json          # JSON format results (if --output-format json/all)
├── report.html           # HTML report with tables and stats (if --output-format html/all)
├── not_vulnerable.csv    # Detected but non-vulnerable devices
├── snapshots/            # Captured camera images
└── log.txt               # Detailed scan log
```

## Using with Port Scanners

For faster scanning, pre-filter targets using a port scanner like masscan:

```bash
# Scan for open camera ports
masscan -p80,8000-8008,554 -iL targets.txt -oL masscan_results.txt --rate 8000

# Format results for Ingram
grep 'open' masscan_results.txt | awk '{printf"%s:%s\n", $4, $3}' > filtered_targets.txt

# Scan only active hosts
python run_ingram.py -i filtered_targets.txt -o output
```

## Disclaimer

This tool is intended for **authorized security testing only**. You must have explicit permission to scan any network or device. Unauthorized scanning is illegal. The authors are not responsible for misuse.

## Credits

- Original project: [jorhelp/Ingram](https://github.com/jorhelp/Ingram)
- [Aiminsun](https://github.com/Aiminsun/CVE-2021-36260) — CVE-2021-36260
- [chrisjd20](https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor) — Hikvision config decryptor
- [mcw0](https://github.com/mcw0/DahuaConsole) — DahuaConsole

## License

Apache 2.0 — See [LICENSE](LICENSE)
