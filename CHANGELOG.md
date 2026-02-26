# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2026-02-26

Major upgrade from the original jorhelp/Ingram scanner.

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
