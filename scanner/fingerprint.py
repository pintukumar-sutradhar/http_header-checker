"""
scanner/fingerprint.py
========================
Passive server / technology fingerprinting based on response headers and
(optionally) response body content. Detects common web servers, CDNs,
reverse proxies, cloud load balancers, frameworks, languages and CMS
platforms without sending any intrusive/active probes.
"""
from __future__ import annotations

import re

from utils.models import FingerprintResult

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:  # pragma: no cover
    _HAS_BS4 = False

# Each entry: (regex pattern applied to a specific header, resulting label)
_SERVER_PATTERNS = [
    (r"nginx", "Nginx"),
    (r"apache", "Apache HTTP Server"),
    (r"litespeed", "LiteSpeed"),
    (r"caddy", "Caddy"),
    (r"microsoft-iis", "Microsoft IIS"),
    (r"cloudflare", "Cloudflare"),
    (r"akamaighost", "Akamai"),
    (r"awselb|amazon", "AWS Elastic Load Balancer"),
    (r"gws", "Google Web Server"),
    (r"openresty", "OpenResty (Nginx+Lua)"),
    (r"tengine", "Tengine (Alibaba Nginx fork)"),
    (r"varnish", "Varnish Cache"),
    (r"haproxy", "HAProxy"),
    (r"jetty", "Jetty"),
    (r"tomcat", "Apache Tomcat"),
    (r"express", "Express (Node.js)"),
    (r"kestrel", "Kestrel (ASP.NET Core)"),
    (r"traefik", "Traefik"),
    (r"fastly", "Fastly"),
    (r"envoy", "Envoy Proxy"),
]

_CDN_HEADER_HINTS = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-akamai-transformed": "Akamai",
    "x-cache": "Generic CDN / Cache Layer",
    "x-served-by": "Fastly / Varnish",
    "x-fastly-request-id": "Fastly",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-azure-ref": "Azure Front Door / CDN",
    "x-vercel-id": "Vercel Edge Network",
    "x-github-request-id": "GitHub Pages / Fastly",
}

_FRAMEWORK_HINTS = {
    "x-powered-by": [
        (r"express", "Express.js"),
        (r"php", "PHP"),
        (r"asp\.net", "ASP.NET"),
        (r"next\.js", "Next.js"),
        (r"laravel", "Laravel"),
    ],
    "x-generator": [
        (r"drupal", "Drupal"),
        (r"wordpress", "WordPress"),
        (r"joomla", "Joomla"),
    ],
    "x-aspnet-version": [(r".*", "ASP.NET")],
    "x-aspnetmvc-version": [(r".*", "ASP.NET MVC")],
}

_CMS_COOKIE_HINTS = {
    "wordpress_": "WordPress",
    "wp-settings": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "csrftoken": "Django",
    "django": "Django",
    "laravel_session": "Laravel",
    "phpsessid": "PHP",
    "jsessionid": "Java (JSP/Servlet)",
    "aspsessionid": "Classic ASP",
    ".aspxauth": "ASP.NET",
}

_CLOUD_HEADER_HINTS = {
    "x-amz-cf-id": ("AWS", "Amazon CloudFront"),
    "x-amz-request-id": ("AWS", None),
    "x-azure-ref": ("Azure", "Azure Front Door"),
    "x-goog-": ("GCP", None),
}


def fingerprint_server(headers: dict[str, str], cookies_raw: list[str] | None = None,
                        body_snippet: str = "") -> FingerprintResult:
    """
    :param headers: lower-cased header name -> value
    :param cookies_raw: raw Set-Cookie header strings
    :param body_snippet: first N KB of the response body, for light content-based hints
    """
    result = FingerprintResult()
    cookies_raw = cookies_raw or []
    technologies: set[str] = set()

    server_value = headers.get("server", "")
    if server_value:
        result.server_banner = server_value
        for pattern, label in _SERVER_PATTERNS:
            if re.search(pattern, server_value, re.IGNORECASE):
                result.web_server = label
                technologies.add(label)
                break

    powered_by = headers.get("x-powered-by")
    if powered_by:
        result.powered_by = powered_by
        technologies.add(powered_by)

    # CDN detection via characteristic headers
    for header_key, cdn_name in _CDN_HEADER_HINTS.items():
        if header_key in headers:
            result.cdn = cdn_name
            technologies.add(cdn_name)
            break
    if server_value and "cloudflare" in server_value.lower():
        result.cdn = "Cloudflare"
        technologies.add("Cloudflare")

    # Reverse proxy detection
    via = headers.get("via", "")
    if via:
        result.reverse_proxy = via
        technologies.add(f"Proxy: {via}")
    if "x-served-by" in headers:
        result.reverse_proxy = result.reverse_proxy or headers["x-served-by"]

    # Framework hints from various headers
    for header_key, patterns in _FRAMEWORK_HINTS.items():
        value = headers.get(header_key)
        if not value:
            continue
        for pattern, label in patterns:
            if re.search(pattern, value, re.IGNORECASE):
                result.framework = label
                technologies.add(label)
                break

    # CMS via cookies
    for cookie_raw in cookies_raw:
        lowered = cookie_raw.lower()
        for hint, cms_name in _CMS_COOKIE_HINTS.items():
            if hint in lowered:
                result.cms = cms_name
                technologies.add(cms_name)

    # CMS / framework via body content (very light heuristics only)
    if body_snippet:
        lowered_body = body_snippet.lower()
        body_hints = {
            "wp-content": "WordPress",
            "wp-includes": "WordPress",
            "sites/default/files": "Drupal",
            "/media/jui/": "Joomla",
            "csrfmiddlewaretoken": "Django",
            "__next_data__": "Next.js",
            "ng-version": "Angular",
            "data-reactroot": "React",
            "vue-app": "Vue.js",
        }
        for hint, label in body_hints.items():
            if hint in lowered_body:
                if not result.cms and label in ("WordPress", "Drupal", "Joomla"):
                    result.cms = label
                technologies.add(label)

    # Cloud provider heuristics
    for header_key, (provider, service) in _CLOUD_HEADER_HINTS.items():
        matched_key = next((h for h in headers if h.startswith(header_key)), None)
        if matched_key:
            technologies.add(provider)
            if service:
                technologies.add(service)

    # OS guess (best-effort, often absent on hardened servers)
    if server_value:
        if "ubuntu" in server_value.lower():
            result.operating_system = "Ubuntu Linux"
        elif "debian" in server_value.lower():
            result.operating_system = "Debian Linux"
        elif "win32" in server_value.lower() or "win64" in server_value.lower():
            result.operating_system = "Windows Server"
        elif "unix" in server_value.lower():
            result.operating_system = "Unix-like"

    result.technologies = sorted(technologies)
    return result
