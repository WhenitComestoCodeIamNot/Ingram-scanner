"""Target discovery via Shodan and Censys APIs"""
import os
import json
import requests

from loguru import logger


def fetch_shodan_targets(api_key, query, output_file, max_results=10000):
    """Fetch targets from Shodan API and write to target file

    Args:
        api_key: Shodan API key
        query: Shodan search query (e.g., 'webcam', 'hikvision', 'port:554')
        output_file: Path to write targets (ip:port format)
        max_results: Maximum number of results to fetch

    Returns:
        int: Number of targets written
    """
    if not api_key:
        logger.error("Shodan API key not provided")
        return 0

    base_url = "https://api.shodan.io"
    count = 0

    try:
        # First, check how many results are available
        info_url = f"{base_url}/shodan/host/count?key={api_key}&query={query}"
        r = requests.get(info_url, timeout=10)
        if r.status_code != 200:
            logger.error(f"Shodan API error: {r.status_code} - {r.text}")
            return 0

        total = r.json().get('total', 0)
        logger.info(f"Shodan found {total} results for query: {query}")

        if total == 0:
            return 0

        # Fetch results page by page
        with open(output_file, 'w') as f:
            page = 1
            while count < min(total, max_results):
                search_url = f"{base_url}/shodan/host/search?key={api_key}&query={query}&page={page}"
                r = requests.get(search_url, timeout=30)

                if r.status_code != 200:
                    logger.error(f"Shodan search error on page {page}: {r.status_code}")
                    break

                data = r.json()
                matches = data.get('matches', [])

                if not matches:
                    break

                for match in matches:
                    ip = match.get('ip_str', '')
                    port = match.get('port', '')
                    if ip and port:
                        f.write(f"{ip}:{port}\n")
                        count += 1

                    if count >= max_results:
                        break

                page += 1

        logger.info(f"Written {count} Shodan targets to {output_file}")

    except Exception as e:
        logger.error(f"Shodan fetch failed: {e}")

    return count


def fetch_censys_targets(api_id, api_secret, query, output_file, max_results=10000):
    """Fetch targets from Censys API and write to target file

    Args:
        api_id: Censys API ID
        api_secret: Censys API secret
        query: Censys search query
        output_file: Path to write targets (ip:port format)
        max_results: Maximum number of results to fetch

    Returns:
        int: Number of targets written
    """
    if not api_id or not api_secret:
        logger.error("Censys API credentials not provided")
        return 0

    base_url = "https://search.censys.io/api/v2"
    count = 0

    try:
        with open(output_file, 'w') as f:
            cursor = None

            while count < max_results:
                params = {
                    'q': query,
                    'per_page': 100,
                }
                if cursor:
                    params['cursor'] = cursor

                r = requests.get(
                    f"{base_url}/hosts/search",
                    params=params,
                    auth=(api_id, api_secret),
                    timeout=30
                )

                if r.status_code != 200:
                    logger.error(f"Censys API error: {r.status_code} - {r.text}")
                    break

                data = r.json()
                result = data.get('result', {})
                hits = result.get('hits', [])

                if not hits:
                    break

                for hit in hits:
                    ip = hit.get('ip', '')
                    services = hit.get('services', [])

                    if ip:
                        if services:
                            for service in services:
                                port = service.get('port', '')
                                if port:
                                    f.write(f"{ip}:{port}\n")
                                    count += 1
                        else:
                            f.write(f"{ip}\n")
                            count += 1

                    if count >= max_results:
                        break

                # Pagination
                links = result.get('links', {})
                cursor = links.get('next', '')
                if not cursor:
                    break

        logger.info(f"Written {count} Censys targets to {output_file}")

    except Exception as e:
        logger.error(f"Censys fetch failed: {e}")

    return count


def generate_targets_from_api(config, output_file):
    """Generate target file from Shodan or Censys based on config

    Args:
        config: Config namedtuple with API keys and queries
        output_file: Path to write the target file

    Returns:
        bool: True if targets were generated, False otherwise
    """
    count = 0

    # Try Shodan first
    shodan_key = getattr(config, 'shodan_key', None)
    shodan_query = getattr(config, 'shodan_query', None)
    if shodan_key and shodan_query:
        logger.info(f"Fetching targets from Shodan: {shodan_query}")
        count += fetch_shodan_targets(shodan_key, shodan_query, output_file)

    # Then Censys
    censys_id = getattr(config, 'censys_id', None)
    censys_secret = getattr(config, 'censys_secret', None)
    censys_query = getattr(config, 'censys_query', None)
    if censys_id and censys_secret and censys_query:
        logger.info(f"Fetching targets from Censys: {censys_query}")
        # Append to same file if Shodan also ran
        mode = 'a' if count > 0 else 'w'
        count += fetch_censys_targets(censys_id, censys_secret, censys_query, output_file)

    if count > 0:
        logger.info(f"Total {count} targets from API sources written to {output_file}")
        return True

    return False
