"""Report generation: JSON and HTML output formats"""
import json
import os
from collections import defaultdict
from datetime import datetime

from loguru import logger


def generate_json_report(results_csv, out_dir, scan_config=None):
    """Generate JSON report from results CSV

    Args:
        results_csv: Path to results.csv file
        out_dir: Output directory
        scan_config: Optional config namedtuple for scan metadata
    """
    if not os.path.exists(results_csv):
        logger.info("No results to generate JSON report")
        return

    vulnerabilities = []
    with open(results_csv, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(',')
            if len(parts) >= 6:
                vulnerabilities.append({
                    'ip': parts[0],
                    'port': parts[1],
                    'device': parts[2],
                    'username': parts[3],
                    'password': parts[4],
                    'vulnerability': parts[5],
                })
            elif len(parts) >= 3:
                vulnerabilities.append({
                    'ip': parts[0],
                    'port': parts[1],
                    'device': parts[2],
                    'username': '',
                    'password': '',
                    'vulnerability': parts[-1] if len(parts) > 3 else '',
                })

    report = {
        'scan_info': {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'total_vulnerabilities': len(vulnerabilities),
            'scanner': 'WRAITH v2.1',
        },
        'vulnerabilities': vulnerabilities,
    }

    # Device type breakdown
    device_counts = defaultdict(int)
    vuln_counts = defaultdict(int)
    for v in vulnerabilities:
        device_counts[v['device']] += 1
        vuln_counts[v['vulnerability']] += 1

    report['summary'] = {
        'by_device': dict(device_counts),
        'by_vulnerability': dict(vuln_counts),
    }

    json_path = os.path.join(out_dir, 'results.json')
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)

    logger.info(f"JSON report saved to {json_path}")


def generate_html_report(results_csv, not_vulnerable_csv, out_dir, scan_config=None):
    """Generate HTML report with tables and summary stats

    Args:
        results_csv: Path to results.csv
        not_vulnerable_csv: Path to not_vulnerable.csv
        out_dir: Output directory
        scan_config: Optional config for metadata
    """
    if not os.path.exists(results_csv):
        logger.info("No results to generate HTML report")
        return

    # Parse results
    vulnerabilities = []
    with open(results_csv, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(',')
            if len(parts) >= 6:
                vulnerabilities.append(parts[:6])
            elif len(parts) >= 3:
                vulnerabilities.append(parts + [''] * (6 - len(parts)))

    # Count not_vulnerable
    not_vuln_count = 0
    if os.path.exists(not_vulnerable_csv):
        with open(not_vulnerable_csv, 'r') as f:
            not_vuln_count = sum(1 for line in f if line.strip())

    # Device breakdown
    device_counts = defaultdict(int)
    vuln_counts = defaultdict(int)
    for v in vulnerabilities:
        device_counts[v[2]] += 1
        vuln_counts[v[5]] += 1

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Build HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WRAITH Scan Report - {timestamp}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #e94560; margin-bottom: 5px; font-size: 28px; }}
        h2 {{ color: #0f3460; background: #16213e; padding: 12px 20px; margin: 25px 0 15px; border-left: 4px solid #e94560; font-size: 18px; color: #eee; }}
        .subtitle {{ color: #888; margin-bottom: 25px; font-size: 14px; }}
        .stats {{ display: flex; gap: 20px; margin-bottom: 25px; flex-wrap: wrap; }}
        .stat-card {{ background: #16213e; border-radius: 8px; padding: 20px; flex: 1; min-width: 150px; text-align: center; }}
        .stat-card .number {{ font-size: 36px; font-weight: bold; color: #e94560; }}
        .stat-card .label {{ font-size: 13px; color: #888; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th {{ background: #16213e; color: #e94560; padding: 12px 15px; text-align: left; font-size: 13px; text-transform: uppercase; }}
        td {{ padding: 10px 15px; border-bottom: 1px solid #2a2a4a; font-size: 14px; }}
        tr:hover {{ background: #16213e; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
        .badge-high {{ background: #e94560; color: white; }}
        .badge-medium {{ background: #f39c12; color: white; }}
        .badge-low {{ background: #27ae60; color: white; }}
        .bar {{ height: 20px; background: #e94560; border-radius: 3px; display: inline-block; min-width: 4px; }}
        .bar-label {{ display: inline-block; min-width: 200px; }}
        .bar-row {{ margin: 5px 0; }}
        .footer {{ text-align: center; color: #555; margin-top: 40px; padding-top: 20px; border-top: 1px solid #2a2a4a; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>WRAITH Scan Report</h1>
        <div class="subtitle">Generated: {timestamp}</div>

        <div class="stats">
            <div class="stat-card">
                <div class="number">{len(vulnerabilities)}</div>
                <div class="label">Vulnerable Devices</div>
            </div>
            <div class="stat-card">
                <div class="number">{not_vuln_count}</div>
                <div class="label">Not Vulnerable</div>
            </div>
            <div class="stat-card">
                <div class="number">{len(device_counts)}</div>
                <div class="label">Device Types</div>
            </div>
            <div class="stat-card">
                <div class="number">{len(vuln_counts)}</div>
                <div class="label">Unique Vulns</div>
            </div>
        </div>

        <h2>Device Breakdown</h2>
"""

    # Device breakdown bars
    if device_counts:
        max_count = max(device_counts.values())
        for device, count in sorted(device_counts.items(), key=lambda x: -x[1]):
            bar_width = int(count / max_count * 300) if max_count > 0 else 0
            html += f"""        <div class="bar-row">
            <span class="bar-label">{device}</span>
            <span class="bar" style="width: {bar_width}px;"></span>
            <span> {count}</span>
        </div>\n"""

    html += """
        <h2>Vulnerability Details</h2>
        <table>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Port</th>
                    <th>Device</th>
                    <th>Username</th>
                    <th>Password</th>
                    <th>Vulnerability</th>
                </tr>
            </thead>
            <tbody>
"""

    for v in vulnerabilities:
        ip, port, device, user, password, vuln = v[0], v[1], v[2], v[3], v[4], v[5]
        # Determine severity badge
        badge_class = 'badge-medium'
        if 'cve' in vuln.lower():
            badge_class = 'badge-high'
        elif 'weak' in vuln.lower():
            badge_class = 'badge-low'
        elif 'bypass' in vuln.lower() or 'disclosure' in vuln.lower():
            badge_class = 'badge-high'

        html += f"""                <tr>
                    <td>{ip}</td>
                    <td>{port}</td>
                    <td>{device}</td>
                    <td>{user}</td>
                    <td>{password}</td>
                    <td><span class="badge {badge_class}">{vuln}</span></td>
                </tr>\n"""

    html += """            </tbody>
        </table>

        <div class="footer">
            Generated by WRAITH v2.1 Network Camera Vulnerability Scanner
        </div>
    </div>
</body>
</html>"""

    html_path = os.path.join(out_dir, 'report.html')
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)

    logger.info(f"HTML report saved to {html_path}")
