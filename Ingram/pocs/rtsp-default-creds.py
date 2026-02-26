from loguru import logger

from .base import POCTemplate
from Ingram.utils.rtsp_probe import RTSP_PATHS, rtsp_describe, rtsp_try_creds


class RTSPDefaultCreds(POCTemplate):
    """RTSP Default Credential Testing

    Tests RTSP streams on port 554/8554 for default credentials.
    Works across all camera brands that expose RTSP.
    """

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        # Special: this POC matches any product that's already been fingerprinted
        # It will also be tried standalone when RTSP port is detected
        self.product = '__rtsp__'
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.medium
        self.desc = """RTSP default credential testing across all camera brands"""

    def verify(self, ip, port=554):
        """Test RTSP streams for default credentials"""
        port = int(port)

        # First, check if RTSP is even responding
        for path in RTSP_PATHS:
            status, response = rtsp_describe(ip, port, path, timeout=self.config.timeout)

            if status == 200:
                # Stream is open without auth!
                return ip, str(port), 'rtsp', 'anonymous', 'none', self.name

            elif status == 401:
                # Auth required - try credentials
                result = rtsp_try_creds(
                    ip, port, path,
                    self.config.users, self.config.passwords,
                    timeout=self.config.timeout
                )
                if result:
                    user, password = result
                    return ip, str(port), 'rtsp', str(user), str(password), self.name
                # If creds failed on this path, move to next
                break  # Most cameras use same auth for all paths

            elif status is None:
                # Connection failed
                return None

        return None

    def exploit(self, results):
        # RTSP streams can't be snapshot via HTTP _snapshot method
        # Just record the finding
        return 0


POCTemplate.register_poc(RTSPDefaultCreds)
