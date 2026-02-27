"""Global configuration"""
import os
from collections import namedtuple

from .utils import net
from .utils.evasion import RateLimiter, ProxyRotator, SCAN_PROFILES


_config = {
    'users': ['admin', 'root', 'default'],
    'passwords': [
        # Generic defaults
        'admin', 'admin12345', 'asdf1234', 'abc12345', '12345admin', '12345abc',
        'password', '123456', '12345', '1234',
        # Amcrest / Dahua
        '888888', '666666',
        # Lorex
        '000000',
        # Common DVR/NVR
        'admin123', 'pass', 'default', 'supervisor',
        # Reolink (blank password)
        '',
    ],
    'user_agent': net.get_user_agent(),  # fallback UA; per-request rotation used when evasion active
    'timeout': 3,
    'ports': [
        # Standard HTTP
        80, 81, 82, 83, 84, 85, 88,
        # Common camera web UI
        8000, 8001, 8080, 8081, 8085, 8086, 8088, 8090, 8181,
        # HTTPS
        443, 8443,
        # RTSP
        554, 8554,
        # Other common camera ports
        2051, 8888, 9000, 9080,
        # Device-specific
        3500,   # Lorex DP Service
        7001, 34567, 37777, 49152, 55555,
    ],

    # rules
    'product': {},
    'rules': set(),

    # file & dir
    'log': 'log.txt',
    'not_vulnerable': 'not_vulnerable.csv',
    'vulnerable': 'results.csv',
    'snapshots': 'snapshots',

    # evasion defaults (overridden by scan_speed profile and CLI args)
    'scan_speed': 'normal',
    'proxy': None,
    'proxy_file': None,
    'delay': None,
    'randomize': True,
    'retries': 2,

    # output
    'output_format': 'csv',
    'disable_rtsp': False,

    # target sources
    'shodan_key': None,
    'shodan_query': None,
    'censys_id': None,
    'censys_secret': None,
    'censys_query': None,

    # deprecated
    'wxuid': '',
    'wxtoken': '',
}


def get_config(args=None):
    # Fingerprint rules
    Rule = namedtuple('Rule', ['product', 'path', 'val'])
    with open(os.path.join(os.path.dirname(__file__), 'rules.csv'), 'r') as f:
        for line in [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]:
            product, path, val = line.split(',', 2)
            _config['rules'].add(Rule(product, path, val))
            _config['product'][product] = product

    # Apply CLI args
    if args:
        for arg in (args := vars(args)):
            if args[arg] is not None:
                _config[arg] = args[arg]

    # Apply scan speed profile
    profile = SCAN_PROFILES.get(_config['scan_speed'], SCAN_PROFILES['normal'])

    # Profile sets th_num only if user didn't explicitly pass -t
    if 'th_num' not in _config or _config.get('th_num') is None:
        _config['th_num'] = profile['th_num']

    # Profile sets delay if user didn't explicitly pass --delay
    if _config.get('delay') is None:
        _config['delay'] = profile.get('min_delay', 0.0)

    # Profile sets randomize if user didn't override
    if 'randomize' not in _config:
        _config['randomize'] = profile.get('randomize', True)

    # Create evasion objects (not stored in namedtuple, attached after)
    min_delay = profile.get('min_delay', 0.0)
    max_delay = profile.get('max_delay', 0.0)
    if _config.get('delay') is not None and _config['delay'] > 0:
        min_delay = _config['delay']
        max_delay = _config['delay'] * 2

    rate_limiter = RateLimiter(min_delay=min_delay, max_delay=max_delay)
    proxy_rotator = ProxyRotator(
        proxy_url=_config.get('proxy'),
        proxy_file=_config.get('proxy_file'),
    )

    # Store objects for access
    _config['rate_limiter'] = rate_limiter
    _config['proxy_rotator'] = proxy_rotator

    Config = namedtuple('config', _config.keys())
    return Config(**_config)
