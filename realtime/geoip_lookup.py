# geoip_lookup.py — IP geolocation with caching and fallback
import json
import ipaddress
import random
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import GEOIP_API_URL, GEOIP_CACHE_SIZE, GEOIP_TIMEOUT

# Try urllib (always available in Python)
from urllib.request import urlopen, Request
from urllib.error import URLError


class GeoIPLookup:
    """
    IP geolocation using the free ip-api.com service.
    Features:
    - LRU cache to avoid redundant lookups
    - Private IP detection
    - Fallback mapping for demo/simulation
    """

    # Simulated GeoIP data for common demo IP ranges
    _SIMULATED_GEO = {
        "203.0.113":   {"country": "China", "countryCode": "CN", "city": "Beijing", "lat": 39.9, "lon": 116.4, "isp": "China Telecom"},
        "198.51.100":  {"country": "Russia", "countryCode": "RU", "city": "Moscow", "lat": 55.75, "lon": 37.62, "isp": "Rostelecom"},
        "45.33.32":    {"country": "United States", "countryCode": "US", "city": "Fremont", "lat": 37.55, "lon": -121.99, "isp": "Linode"},
        "185.220.101": {"country": "Germany", "countryCode": "DE", "city": "Berlin", "lat": 52.52, "lon": 13.41, "isp": "Tor Exit Node"},
        "91.219.236":  {"country": "Romania", "countryCode": "RO", "city": "Bucharest", "lat": 44.43, "lon": 26.10, "isp": "M247 Ltd"},
        "77.247.181":  {"country": "Netherlands", "countryCode": "NL", "city": "Amsterdam", "lat": 52.37, "lon": 4.90, "isp": "Tor Exit Node"},
    }

    # Extra random locations for variety in simulation
    _RANDOM_LOCATIONS = [
        {"country": "Brazil", "countryCode": "BR", "city": "São Paulo", "lat": -23.55, "lon": -46.63, "isp": "NET Virtua"},
        {"country": "India", "countryCode": "IN", "city": "Mumbai", "lat": 19.08, "lon": 72.88, "isp": "Reliance Jio"},
        {"country": "Japan", "countryCode": "JP", "city": "Tokyo", "lat": 35.68, "lon": 139.69, "isp": "NTT Communications"},
        {"country": "South Korea", "countryCode": "KR", "city": "Seoul", "lat": 37.57, "lon": 126.98, "isp": "Korea Telecom"},
        {"country": "United Kingdom", "countryCode": "GB", "city": "London", "lat": 51.51, "lon": -0.13, "isp": "British Telecom"},
        {"country": "Australia", "countryCode": "AU", "city": "Sydney", "lat": -33.87, "lon": 151.21, "isp": "Telstra"},
        {"country": "Nigeria", "countryCode": "NG", "city": "Lagos", "lat": 6.45, "lon": 3.40, "isp": "MTN Nigeria"},
        {"country": "Ukraine", "countryCode": "UA", "city": "Kyiv", "lat": 50.45, "lon": 30.52, "isp": "Datagroup"},
        {"country": "Iran", "countryCode": "IR", "city": "Tehran", "lat": 35.69, "lon": 51.39, "isp": "TIC"},
        {"country": "Turkey", "countryCode": "TR", "city": "Istanbul", "lat": 41.01, "lon": 28.98, "isp": "Turk Telekom"},
    ]

    def __init__(self):
        self._cache = {}

    # RFC1918 private ranges + loopback — only these are "Local Network"
    _PRIVATE_NETS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
    ]

    def _is_private(self, ip):
        """Check if an IP is in RFC1918 private range or loopback."""
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._PRIVATE_NETS)
        except ValueError:
            return True

    def lookup(self, ip):
        """
        Look up geolocation for an IP address.
        Returns dict with: country, countryCode, city, lat, lon, isp
        """
        if not ip or self._is_private(ip):
            return {
                "country": "Local Network", "countryCode": "LO",
                "city": "Internal", "lat": None, "lon": None, "isp": "LAN"
            }

        # Check cache
        if ip in self._cache:
            return self._cache[ip]

        # Check simulated data first (for known demo/simulation IP prefixes)
        prefix = ".".join(ip.split(".")[:3])
        if prefix in self._SIMULATED_GEO:
            result = dict(self._SIMULATED_GEO[prefix])
        else:
            # Try API lookup for unknown external IPs
            result = self._api_lookup(ip)
            # Fallback to simulated random data
            if not result:
                result = self._simulated_lookup(ip)

        # Cache result
        if len(self._cache) >= GEOIP_CACHE_SIZE:
            # Evict oldest entries
            keys = list(self._cache.keys())[:100]
            for k in keys:
                del self._cache[k]
        self._cache[ip] = result

        return result

    def _api_lookup(self, ip):
        """Call ip-api.com for real geolocation."""
        try:
            url = GEOIP_API_URL.format(ip=ip)
            req = Request(url, headers={"User-Agent": "AI-IDS/1.0"})
            with urlopen(req, timeout=GEOIP_TIMEOUT) as resp:
                data = json.loads(resp.read().decode())
                if data.get("status") == "success":
                    return {
                        "country": data.get("country", "Unknown"),
                        "countryCode": data.get("countryCode", "??"),
                        "city": data.get("city", "Unknown"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "isp": data.get("isp", "Unknown")
                    }
        except Exception:
            pass
        return None

    def _simulated_lookup(self, ip):
        """Return simulated GeoIP data based on IP prefix."""
        # Check known prefixes
        prefix = ".".join(ip.split(".")[:3])
        if prefix in self._SIMULATED_GEO:
            return dict(self._SIMULATED_GEO[prefix])

        # Random location for unknown IPs
        loc = random.choice(self._RANDOM_LOCATIONS)
        # Add slight random offset for variety
        return {
            "country": loc["country"],
            "countryCode": loc["countryCode"],
            "city": loc["city"],
            "lat": loc["lat"] + random.uniform(-0.5, 0.5),
            "lon": loc["lon"] + random.uniform(-0.5, 0.5),
            "isp": loc["isp"]
        }
