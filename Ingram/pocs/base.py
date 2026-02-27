import os
import requests
from collections import namedtuple

from loguru import logger


# Ports that should use HTTPS
HTTPS_PORTS = {'443', '8443'}


def get_scheme(port):
    """Return 'https' for HTTPS ports, 'http' otherwise"""
    return 'https' if str(port) in HTTPS_PORTS else 'http'


class POCTemplate:

    level = namedtuple('level', 'high medium low')('high', 'medium', 'low')
    poc_classes = []

    @staticmethod
    def register_poc(self):
        self.poc_classes.append(self)

    def __init__(self, config):
        self.config = config
        self.name = self.get_file_name(__file__)
        self.product = 'base'
        self.product_version = ''
        self.ref = ''
        self.level = self.level.low
        self.desc = """"""

    def get_file_name(self, file):
        return os.path.basename(file).split('.')[0]

    def _get_url(self, ip, port, path=''):
        """Build URL with correct scheme based on port"""
        scheme = get_scheme(port)
        return f"{scheme}://{ip}:{port}{path}"

    def _get_headers(self):
        """Get randomized headers for evasion"""
        try:
            from ..utils.evasion import get_random_headers
            return get_random_headers()
        except Exception:
            return {'Connection': 'close', 'User-Agent': self.config.user_agent}

    def _get_proxies(self):
        """Get proxy dict if configured"""
        try:
            return self.config.proxy_rotator.get_proxy()
        except Exception:
            return None

    def verify(self, ip, port):
        """Verify if the vulnerability exists.
        params:
        - ip: IP address, str
        - port: port number, str or num

        return:
        - Success: (ip, port, self.product, user, password, self.name)
        - Failure: None
        """
        pass

    def _snapshot(self, url, img_file_name, auth=None) -> int:
        """Download image from url and save to file"""
        img_path = os.path.join(self.config.out_dir, self.config.snapshots, img_file_name)
        headers = self._get_headers()
        proxies = self._get_proxies()
        try:
            if auth:
                res = requests.get(url, auth=auth, timeout=self.config.timeout, verify=False, headers=headers, stream=True, proxies=proxies)
            else:
                res = requests.get(url, timeout=self.config.timeout, verify=False, headers=headers, stream=True, proxies=proxies)
            if res.status_code == 200 and 'head' not in res.text:
                with open(img_path, 'wb') as f:
                    for content in res.iter_content(10240):
                        f.write(content)
                return 1
        except Exception as e:
            logger.error(e)
        return 0

    def exploit(self, results: tuple) -> int:
        """Exploit the vulnerability, mainly to capture snapshots.
        params:
        - results: return value from verify() on success
        return:
        - number of snapshots captured (usually 1 or 0)
        """
        url = ''
        img_file_name = ''
        return self._snapshot(url, img_file_name)
