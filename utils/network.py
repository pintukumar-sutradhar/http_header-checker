"""
utils/network.py
=================
Low level networking helper functions shared by the scanner modules:
DNS resolution (IPv4/IPv6), reverse DNS, IP geolocation / hosting provider
lookup, and URL validation.
"""
from __future__ import annotations

import random
import socket
from typing import Optional
from urllib.parse import urlparse

import requests

from .constants import USER_AGENTS, DEFAULT_USER_AGENT
from .logger import get_logger

logger = get_logger()


def normalize_url(raw_url: str) -> str:
    """Ensure the URL has a scheme; default to https if omitted."""
    raw_url = raw_url.strip()
    if not raw_url:
        return raw_url
    if "://" not in raw_url:
        raw_url = "https://" + raw_url
    return raw_url


def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https"), result.netloc])
    except Exception:
        return False


def resolve_ipv4(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except Exception as exc:
        logger.debug(f"IPv4 resolution failed for {hostname}: {exc}")
        return None


def resolve_ipv6(hostname: str) -> Optional[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET6)
        if infos:
            return infos[0][4][0]
    except Exception as exc:
        logger.debug(f"IPv6 resolution failed for {hostname}: {exc}")
    return None


def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception as exc:
        logger.debug(f"Reverse DNS failed for {ip}: {exc}")
        return None


def geolocate_ip(ip: str, timeout: int = 6) -> dict:
    """Best-effort free IP geolocation lookup (no API key required).

    Falls back gracefully -- geolocation is informational only and should
    never break the main scan flow.
    """
    result = {"country": None, "hosting_provider": None, "asn": None}
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,isp,org,as"},
            timeout=timeout,
        )
        data = resp.json()
        if data.get("status") == "success":
            result["country"] = data.get("country")
            result["hosting_provider"] = data.get("isp") or data.get("org")
            result["asn"] = data.get("as")
    except Exception as exc:
        logger.debug(f"Geolocation lookup failed for {ip}: {exc}")
    return result


def pick_user_agent(mode: str = "default", custom_ua: str = "") -> str:
    """Return a User-Agent string based on the requested mode."""
    if mode == "random":
        return random.choice(USER_AGENTS)
    if mode == "custom" and custom_ua.strip():
        return custom_ua.strip()
    return DEFAULT_USER_AGENT


def get_hostname(url: str) -> str:
    return urlparse(url).hostname or ""
