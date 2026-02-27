"""Command-line argument parsing"""
import argparse


def get_parse():
    parser = argparse.ArgumentParser(description='WRAITH - Network Camera Vulnerability Scanner')

    # Required arguments
    parser.add_argument('-i', '--in_file', type=str, required=True, help='target file with IPs/ranges (one per line)')
    parser.add_argument('-o', '--out_dir', type=str, required=True, help='output directory for results')

    # Scanning options
    parser.add_argument('-p', '--ports', type=int, nargs='+', default=None, help='port(s) to scan')
    parser.add_argument('-t', '--th_num', type=int, default=None, help='worker/coroutine count (default: set by scan speed)')
    parser.add_argument('-T', '--timeout', type=int, default=3, help='request timeout in seconds (default: 3)')
    parser.add_argument('--retries', type=int, default=2, help='max retries per request (default: 2)')

    # Evasion options
    parser.add_argument('-S', '--scan_speed', type=str, default='normal',
                        choices=['stealth', 'normal', 'aggressive'],
                        help='scan speed profile (default: normal)')
    parser.add_argument('--proxy', type=str, default=None, help='proxy URL (http/socks4/socks5)')
    parser.add_argument('--proxy-file', type=str, default=None, dest='proxy_file',
                        help='file with proxy list (one per line, rotated)')
    parser.add_argument('--delay', type=float, default=None, help='min delay between requests per target (seconds)')
    parser.add_argument('--randomize', action='store_true', default=True, help='shuffle target order (default: on)')
    parser.add_argument('--no-randomize', action='store_false', dest='randomize',
                        help='scan targets in sequential order')

    # Output options
    parser.add_argument('--output-format', type=str, default='csv', dest='output_format',
                        choices=['csv', 'json', 'html', 'all'],
                        help='output format (default: csv)')
    parser.add_argument('-D', '--disable_snapshot', action='store_true', help='disable snapshot capture')
    parser.add_argument('--disable-rtsp', action='store_true', dest='disable_rtsp',
                        help='disable RTSP stream detection')

    # Target sources
    parser.add_argument('--shodan-key', type=str, default=None, dest='shodan_key', help='Shodan API key')
    parser.add_argument('--shodan-query', type=str, default=None, dest='shodan_query', help='Shodan search query')
    parser.add_argument('--censys-id', type=str, default=None, dest='censys_id', help='Censys API ID')
    parser.add_argument('--censys-secret', type=str, default=None, dest='censys_secret', help='Censys API secret')
    parser.add_argument('--censys-query', type=str, default=None, dest='censys_query', help='Censys search query')

    # Other
    parser.add_argument('--debug', action='store_true', help='enable debug logging')

    args = parser.parse_args()
    return args
