# Changelog

All notable changes to this project will be documented in this file.

## [2.1.0] - 2026-02-26

Bug fixes for zero-detection scanning issues and expanded CVE coverage through 2025.

### Fixed

**Critical: HTTPS Fingerprinting Bug**
- `fingerprint.py` hardcoded `http://` for all ports — cameras on HTTPS ports (443, 8443) were completely invisible
- Added `_get_scheme(port)` to correctly use `https://` for HTTPS ports
- Added SSL fallback: if HTTPS fails, tries HTTP (and vice versa)

**Critical: Title XPath IndexError**
- `html.xpath('//title')[0]` crashed silently when pages had no `<title>` tag
- Added guard check before accessing index

**High: Body Matching Failure on SPA Devices**
- Original used XPath `//body` which failed on JS-rendered single-page apps
- Changed to search `req.text.lower()` directly for reliable detection

**Medium: Fingerprinting Bypassed Evasion System**
- `fingerprint.py` used static `config.user_agent` and no proxy
- Now uses `get_random_headers()` and `config.proxy_rotator.get_proxy()`

**Medium: All 33 POCs Hardcoded `http://`**
- Every existing POC used `f"http://{ip}:{port}..."` ignoring HTTPS ports
- Updated all POCs to use `self._get_url()`, `self._get_headers()`, `self._get_proxies()` helpers

**Minor: RTSP Port Double-Scanning**
- Ports 554/8554 were scanned in the main HTTP loop AND the RTSP probe
- Main loop now skips RTSP-only ports; they're handled by the dedicated RTSP prober

### Added

**9 New CVE Exploits**
- CVE-2024-7029 — AVTECH command injection (CVSS 8.8, CISA KEV, 38K+ exposed devices)
- CVE-2023-21413 — Axis OS command injection (CVSS 9.1)
- CVE-2023-21415 — Axis VAPIX API path traversal (CVSS 6.5)
- CVE-2023-52163 — DigiEver NVR command injection (CVSS 8.8, CISA KEV, Mirai botnet)
- CVE-2023-30353 — Tenda CP3 unauthenticated RCE (CVSS 9.8)
- CVE-2025-31700 — Dahua pre-auth RCE via ONVIF Host header overflow (CVSS 8.1)
- CVE-2023-48121 — Ezviz camera authentication bypass
- CVE-2024-52544 — Lorex stack buffer overflow (Pwn2Own 2024)
- CVE-2021-45039 — Uniview pre-auth RCE via UDP 7788 (CVSS 8.9)

**3 New Device Brands**
- Ezviz — fingerprint rules + CVE-2023-48121 auth bypass POC
- DigiEver — fingerprint rules + CVE-2023-52163 command injection POC
- Hanwha Wisenet — fingerprint rules

**Expanded Fingerprint Rules**
- Added body/header-based rules for AVTECH, Axis, Dahua, D-Link, DVR, Uniview, Tenda, TP-Link VIGI, Lorex, Honeywell, Reolink, Ezviz, DigiEver, Hanwha

**POC Base Class Improvements**
- Added `_get_url(ip, port, path)` — auto-detects HTTP vs HTTPS based on port
- Added `_get_headers()` — returns randomized headers per request
- Added `_get_proxies()` — returns proxy dict from proxy rotator
- Changed vulnerability level names from Chinese to English

### Changed
- Default timeout explicitly set to 3 seconds
- Added port 3500 (Lorex DP Service) to default port list
- Fingerprint error logging changed from `logger.error` to `logger.debug` (less noise)
- Total CVE coverage: 22 CVEs (was 13), spanning 2017-2025

---

## [2.0.0] - 2026-02-26

Major upgrade from the original Ingram scanner (jorhelp/Ingram). Renamed to WRAITH.

### Added

**Anti-Detection & Evasion**
- Rate limiting with configurable per-target request throttling
- User-Agent rotation per request (was static for entire scan)
- HTTP header randomization (Accept-Language, DNT, Sec-Fetch-*, etc.)
- Proxy support: HTTP, SOCKS4, SOCKS5 via `--proxy`
- Proxy list rotation via `--proxy-file`
- Target IP randomization (shuffle scan order to avoid sequential detection)
- Scan speed profiles: `stealth`, `normal`, `aggressive` via `-S`

**New Device Support**
- Reolink — fingerprinting + weak password POC
- Amcrest — fingerprinting + weak password + info disclosure POC
- Lorex — fingerprinting + weak password POC
- Honeywell — fingerprinting + weak password POC
- Foscam — fingerprinting + weak password POC
- TP-Link — fingerprinting rules

**New CVE POCs (2022-2025)**
- CVE-2022-30563 — Dahua ONVIF authentication bypass
- CVE-2023-6895 — Hikvision/DVR command injection (CVSS 9.8)
- CVE-2023-28808 — Hikvision access control auth bypass (CVSS 9.1)
- Amcrest unauthenticated info disclosure (`/web_caps/webCapsConfig`)

**RTSP Stream Detection**
- RTSP probing on ports 554 and 8554
- Default credential testing for RTSP streams
- Brand-specific RTSP path detection (Hikvision, Dahua, Reolink, Foscam, etc.)

**Output & Reporting**
- JSON output format (`results.json`)
- HTML report with summary stats, device breakdown, and vulnerability tables
- `--output-format` flag: csv, json, html, all

**Target Discovery**
- Shodan integration via `--shodan-key` and `--shodan-query`
- Censys integration via `--censys-id`, `--censys-secret`, `--censys-query`

**Reliability**
- Retry logic with exponential backoff (`--retries`)
- Python 3.11+ compatibility (pwntools made optional)

### Changed
- Expanded default credentials: 18 passwords (was 6) including brand-specific defaults
- Expanded default ports: added 554, 8554, 443, 8443, 8888, 34567, and more
- README rewritten entirely in English
- Platform support: Windows now fully supported alongside Linux and Mac

### Fixed
- Python 3.11 compatibility issues with pwntools dependency

## [1.0.0] - Original

Original release by [jorhelp/Ingram](https://github.com/jorhelp/Ingram).

- 26 POCs for 17 device types
- CVEs: 2017-7921, 2017-14514, 2018-6479, 2018-9995, 2018-17240, 2020-25078, 2021-33044, 2021-33045, 2021-36260
- Weak password testing for Hikvision, Dahua, Xiongmai, Uniview, Avtech, Axis, D-Link DCS, DVR, GeoVision, Instar, IPC Camera, Netwave, Nuuo, ReeCam, Tenda
- gevent-based async scanning
- CSV output with snapshot capture
- Resume capability
