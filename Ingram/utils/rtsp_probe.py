"""RTSP stream detection and probing"""
import socket
import base64

from loguru import logger


# Common RTSP paths by brand
RTSP_PATHS = [
    '/Streaming/Channels/101',          # Hikvision
    '/cam/realmonitor?channel=1&subtype=0',  # Dahua
    '/h264Preview_01_main',              # Reolink
    '/live/ch00_0',                      # Generic
    '/11',                               # Foscam
    '/videoMain',                        # Various
    '/',                                 # Root
    '/live',                             # Generic
    '/stream1',                          # Generic
    '/MediaInput/h264',                  # Axis
]

RTSP_PORTS = [554, 8554]


def rtsp_describe(ip, port, path='/', user=None, password=None, timeout=3):
    """Send RTSP DESCRIBE request and return status code

    Returns:
        tuple: (status_code, response_text) or (None, None) on failure
        - 200: Stream accessible (no auth or auth succeeded)
        - 401: Auth required
        - 403: Forbidden
        - None: Connection failed
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        s.connect((ip, int(port)))

        rtsp_url = f"rtsp://{ip}:{port}{path}"

        # Build DESCRIBE request
        request = f"DESCRIBE {rtsp_url} RTSP/1.0\r\n"
        request += f"CSeq: 1\r\n"
        request += f"User-Agent: LibVLC/3.0.18\r\n"

        if user is not None and password is not None:
            credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
            request += f"Authorization: Basic {credentials}\r\n"

        request += "\r\n"

        s.sendall(request.encode())

        response = b""
        while True:
            try:
                data = s.recv(4096)
                if not data:
                    break
                response += data
                if b"\r\n\r\n" in response:
                    break
            except socket.timeout:
                break

        response_text = response.decode('utf-8', errors='ignore')

        # Parse status code
        if response_text.startswith('RTSP/'):
            parts = response_text.split(' ', 2)
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                    return status_code, response_text
                except ValueError:
                    pass

        return None, response_text

    except Exception as e:
        logger.debug(f"RTSP probe failed for {ip}:{port}{path}: {e}")
        return None, None

    finally:
        s.close()


def rtsp_probe(ip, port, timeout=3):
    """Probe an RTSP port to check if it's a camera stream

    Returns:
        str: First accessible RTSP path, or None if not accessible
    """
    for path in RTSP_PATHS[:3]:  # Only try first 3 common paths for speed
        status, _ = rtsp_describe(ip, port, path, timeout=timeout)
        if status in (200, 401, 403):
            return path
    return None


def rtsp_try_creds(ip, port, path, users, passwords, timeout=3):
    """Try credential combinations against RTSP

    Returns:
        tuple: (user, password) on success, None on failure
    """
    for user in users:
        for password in passwords:
            status, response = rtsp_describe(ip, port, path, user, password, timeout)
            if status == 200:
                return user, password
            elif status == 401:
                continue  # Auth required, try next combo
            elif status is None:
                return None  # Connection failed, stop trying
    return None
