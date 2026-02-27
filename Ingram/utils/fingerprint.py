"""Device fingerprinting via HTTP response analysis"""
import hashlib
import re
import requests

from loguru import logger
from lxml import etree

from .evasion import get_random_headers


# Ports that should use HTTPS
HTTPS_PORTS = {'443', '8443'}


def _get_scheme(port):
    """Return 'https' for HTTPS ports, 'http' otherwise"""
    return 'https' if str(port) in HTTPS_PORTS else 'http'


def _parse(req, rule_val):
    """Check if response matches fingerprint rule.
    rule_val may be multiple AND conditions: xxx&&xxx...
    """
    def check_one(item):
        match = re.search(r'(.*)=`(.*)`', item)
        if not match:
            return False
        left, right = match.groups()

        if left == 'md5':
            if hashlib.md5(req.content).hexdigest() == right:
                return True
        elif left == 'title':
            try:
                html = etree.HTML(req.text)
                titles = html.xpath('//title')
                if titles:
                    title_text = titles[0].xpath('string(.)').lower()
                    if right.lower() in title_text:
                        return True
            except Exception:
                pass
        elif left == 'body':
            # Search the full response text directly instead of XPath
            # This handles both static HTML and JS-rendered content markers
            if right.lower() in req.text.lower():
                return True
        elif left == 'headers':
            for header_item in req.headers.items():
                if right.lower() in ''.join(header_item).lower():
                    return True
        elif left == 'status_code':
            return int(req.status_code) == int(right)
        return False

    return all(map(check_one, rule_val.split('&&')))


def fingerprint(ip, port, config):
    req_dict = {}
    session = requests.session()
    headers = get_random_headers()

    # Use proxy if configured
    proxies = config.proxy_rotator.get_proxy() if hasattr(config, 'proxy_rotator') else None

    scheme = _get_scheme(port)

    for rule in config.rules:
        try:
            url = f"{scheme}://{ip}:{port}{rule.path}"
            req = req_dict.get(rule.path) or session.get(
                url,
                headers=headers,
                timeout=config.timeout,
                verify=False,
                proxies=proxies,
            )
            # Cache only status_code 200 responses
            if (rule.path not in req_dict) and (req.status_code == 200):
                req_dict[rule.path] = req
            if _parse(req, rule.val):
                return rule.product
        except requests.exceptions.SSLError:
            # If HTTPS fails, try HTTP as fallback (and vice versa)
            try:
                fallback_scheme = 'http' if scheme == 'https' else 'https'
                fallback_url = f"{fallback_scheme}://{ip}:{port}{rule.path}"
                req = session.get(
                    fallback_url,
                    headers=headers,
                    timeout=config.timeout,
                    verify=False,
                    proxies=proxies,
                )
                if (rule.path not in req_dict) and (req.status_code == 200):
                    req_dict[rule.path] = req
                if _parse(req, rule.val):
                    return rule.product
            except Exception:
                pass
        except Exception as e:
            logger.debug(f"Fingerprint {ip}:{port}{rule.path}: {e}")
    return None
