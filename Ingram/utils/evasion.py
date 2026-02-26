"""Anti-detection and evasion utilities"""
import random
import time
from collections import defaultdict
from itertools import cycle
from threading import Lock

from loguru import logger


class RateLimiter:
    """Per-target rate limiting with configurable delay and jitter"""

    def __init__(self, min_delay=0.0, max_delay=0.0):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self._last_request = defaultdict(float)
        self._lock = Lock()

    def wait(self, target_ip=None):
        """Wait before making a request to target_ip"""
        if self.min_delay <= 0 and self.max_delay <= 0:
            return

        delay = random.uniform(self.min_delay, self.max_delay) if self.max_delay > self.min_delay else self.min_delay

        if target_ip:
            with self._lock:
                elapsed = time.time() - self._last_request[target_ip]
                if elapsed < delay:
                    time.sleep(delay - elapsed)
                self._last_request[target_ip] = time.time()
        else:
            time.sleep(delay)


class ProxyRotator:
    """Rotate through a list of proxy URLs"""

    def __init__(self, proxy_url=None, proxy_file=None):
        self.proxies = []
        self._cycle = None
        self._lock = Lock()

        if proxy_url:
            self.proxies = [proxy_url]
        elif proxy_file:
            try:
                with open(proxy_file, 'r') as f:
                    self.proxies = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except Exception as e:
                logger.error(f"Failed to load proxy file: {e}")

        if self.proxies:
            self._cycle = cycle(self.proxies)
            logger.info(f"Loaded {len(self.proxies)} proxies")

    def get_proxy(self):
        """Get the next proxy in rotation. Returns dict for requests or None."""
        if not self._cycle:
            return None
        with self._lock:
            proxy_url = next(self._cycle)
        return {'http': proxy_url, 'https': proxy_url}

    @property
    def enabled(self):
        return bool(self.proxies)


# Scan speed presets
SCAN_PROFILES = {
    'stealth': {
        'min_delay': 1.0,
        'max_delay': 3.0,
        'th_num': 20,
        'randomize': True,
    },
    'normal': {
        'min_delay': 0.0,
        'max_delay': 0.0,
        'th_num': 150,
        'randomize': True,
    },
    'aggressive': {
        'min_delay': 0.0,
        'max_delay': 0.0,
        'th_num': 300,
        'randomize': False,
    },
}


def get_random_headers(user_agent=None):
    """Generate randomized browser-like HTTP headers"""
    from . import net

    ua = user_agent or net.get_user_agent()

    accept_languages = [
        'en-US,en;q=0.9',
        'en-GB,en;q=0.9',
        'en-US,en;q=0.5',
        'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
        'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7',
        'es-ES,es;q=0.9,en;q=0.8',
        'zh-CN,zh;q=0.9,en;q=0.8',
        'ja-JP,ja;q=0.9,en;q=0.8',
        'ko-KR,ko;q=0.9,en;q=0.8',
        'pt-BR,pt;q=0.9,en;q=0.8',
    ]

    accept_encodings = [
        'gzip, deflate',
        'gzip, deflate, br',
        'gzip',
        'identity',
    ]

    headers = {
        'User-Agent': ua,
        'Accept': random.choice([
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            '*/*',
        ]),
        'Accept-Language': random.choice(accept_languages),
        'Accept-Encoding': random.choice(accept_encodings),
        'Connection': random.choice(['keep-alive', 'close']),
    }

    # Randomly add some modern browser headers
    if random.random() > 0.5:
        headers['DNT'] = '1'
    if random.random() > 0.6:
        headers['Upgrade-Insecure-Requests'] = '1'
    if random.random() > 0.7:
        headers['Sec-Fetch-Site'] = random.choice(['none', 'same-origin', 'cross-site'])
        headers['Sec-Fetch-Mode'] = random.choice(['navigate', 'no-cors', 'cors'])
        headers['Sec-Fetch-Dest'] = random.choice(['document', 'empty'])

    return headers


def retry_request(func, max_retries=2, backoff_base=1.0):
    """Decorator for retrying failed HTTP requests with exponential backoff"""
    def wrapper(*args, **kwargs):
        last_exception = None
        for attempt in range(max_retries + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if attempt < max_retries:
                    delay = backoff_base * (2 ** attempt) + random.uniform(0, 0.5)
                    time.sleep(delay)
                    logger.debug(f"Retry {attempt + 1}/{max_retries} after {delay:.1f}s: {e}")
        logger.error(f"All {max_retries} retries failed: {last_exception}")
        return None
    return wrapper
