"""
scanner/header_definitions.py
==============================
Knowledge base describing every HTTP header the analyzer understands:
security purpose, OWASP/Mozilla/Microsoft guidance, recommended secure
values, and default risk severity if the header is missing.

This is intentionally data-only (no logic) so it can be extended easily by
adding new entries -- e.g. to support a brand-new header that appears in a
future browser spec, just append a new ``HeaderDefinition``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from utils.models import Severity


@dataclass
class HeaderDefinition:
    name: str
    category: str
    security_relevant: bool
    missing_severity: Severity
    description: str
    why_it_matters: str
    recommended_value: str
    owasp_reference: str = ""
    mozilla_recommendation: str = ""
    microsoft_recommendation: str = ""
    example_secure_config: str = ""
    deprecated: bool = False
    weak_values: list[str] = field(default_factory=list)


HEADER_DB: dict[str, HeaderDefinition] = {}


def _add(defn: HeaderDefinition) -> None:
    HEADER_DB[defn.name.lower()] = defn


# --------------------------------------------------------------------------- #
# Core security headers
# --------------------------------------------------------------------------- #
_add(HeaderDefinition(
    name="Strict-Transport-Security",
    category="Transport Security",
    security_relevant=True,
    missing_severity=Severity.HIGH,
    description="Instructs browsers to only ever connect using HTTPS for this domain.",
    why_it_matters="Without HSTS, users can be forced onto plaintext HTTP by network "
                   "attackers (SSL-stripping) even if the site normally redirects to HTTPS.",
    recommended_value="max-age=63072000; includeSubDomains; preload",
    owasp_reference="https://owasp.org/www-project-secure-headers/#http-strict-transport-security",
    mozilla_recommendation="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    microsoft_recommendation="Enable HSTS at the IIS/reverse-proxy layer with a long max-age.",
    example_secure_config="Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    weak_values=["max-age=0"],
))

_add(HeaderDefinition(
    name="Content-Security-Policy",
    category="Content Security",
    security_relevant=True,
    missing_severity=Severity.HIGH,
    description="Restricts the sources from which content (scripts, styles, images, etc.) may be loaded.",
    why_it_matters="A strong CSP is one of the most effective mitigations against Cross-Site "
                   "Scripting (XSS) and data-injection attacks.",
    recommended_value="default-src 'self'; script-src 'self'; object-src 'none'; "
                       "frame-ancestors 'none'; base-uri 'self'; upgrade-insecure-requests",
    owasp_reference="https://owasp.org/www-project-secure-headers/#content-security-policy",
    mozilla_recommendation="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    microsoft_recommendation="Define an explicit allow-list; avoid 'unsafe-inline'/'unsafe-eval'.",
    example_secure_config="Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'",
))

_add(HeaderDefinition(
    name="X-Frame-Options",
    category="Clickjacking Protection",
    security_relevant=True,
    missing_severity=Severity.MEDIUM,
    description="Controls whether the page can be rendered inside an <iframe>.",
    why_it_matters="Prevents clickjacking attacks where an attacker overlays your site in a "
                   "transparent iframe to trick users into clicking hidden UI elements.",
    recommended_value="DENY or SAMEORIGIN",
    owasp_reference="https://owasp.org/www-project-secure-headers/#x-frame-options",
    mozilla_recommendation="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    microsoft_recommendation="Superseded by CSP frame-ancestors, but still recommended for legacy browsers.",
    example_secure_config="X-Frame-Options: DENY",
    weak_values=["allow-from"],
))

_add(HeaderDefinition(
    name="X-Content-Type-Options",
    category="MIME Security",
    security_relevant=True,
    missing_severity=Severity.MEDIUM,
    description="Prevents browsers from MIME-sniffing a response away from its declared Content-Type.",
    why_it_matters="Stops attacks where a malicious file disguised as an image/text is executed as "
                   "script or HTML due to content-type sniffing.",
    recommended_value="nosniff",
    owasp_reference="https://owasp.org/www-project-secure-headers/#x-content-type-options",
    mozilla_recommendation="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    microsoft_recommendation="Always set to 'nosniff' on all responses.",
    example_secure_config="X-Content-Type-Options: nosniff",
))

_add(HeaderDefinition(
    name="Referrer-Policy",
    category="Privacy",
    security_relevant=True,
    missing_severity=Severity.LOW,
    description="Controls how much referrer information is included with requests made from the page.",
    why_it_matters="Weak referrer policies can leak sensitive URL parameters (tokens, session data) "
                   "to third-party sites.",
    recommended_value="strict-origin-when-cross-origin or no-referrer",
    owasp_reference="https://owasp.org/www-project-secure-headers/#referrer-policy",
    mozilla_recommendation="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    microsoft_recommendation="Use 'strict-origin-when-cross-origin' as a safe default.",
    example_secure_config="Referrer-Policy: strict-origin-when-cross-origin",
))

_add(HeaderDefinition(
    name="Permissions-Policy",
    category="Feature Control",
    security_relevant=True,
    missing_severity=Severity.LOW,
    description="Allows fine-grained control over which browser features/APIs the page may use "
                "(camera, microphone, geolocation, etc.).",
    why_it_matters="Reduces attack surface from malicious or compromised third-party scripts abusing "
                   "powerful browser APIs.",
    recommended_value="camera=(), microphone=(), geolocation=(), interest-cohort=()",
    owasp_reference="https://owasp.org/www-project-secure-headers/#permissions-policy",
    mozilla_recommendation="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    microsoft_recommendation="Explicitly disable unused features.",
    example_secure_config="Permissions-Policy: camera=(), microphone=(), geolocation=()",
))

_add(HeaderDefinition(
    name="X-XSS-Protection",
    category="Legacy XSS Protection",
    security_relevant=True,
    missing_severity=Severity.INFO,
    description="Legacy header that enabled the browser's built-in reflected-XSS filter.",
    why_it_matters="Deprecated by modern browsers in favor of CSP; setting it to '1; mode=block' is "
                   "harmless but no longer provides real protection in current Chrome/Edge/Firefox.",
    recommended_value="0 (disable legacy filter) or rely on CSP entirely",
    owasp_reference="https://owasp.org/www-project-secure-headers/#x-xss-protection",
    mozilla_recommendation="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
    microsoft_recommendation="Not required on modern stacks; rely on CSP.",
    example_secure_config="X-XSS-Protection: 0",
    deprecated=True,
))

_add(HeaderDefinition(
    name="Cross-Origin-Opener-Policy",
    category="Cross-Origin Isolation",
    security_relevant=True,
    missing_severity=Severity.LOW,
    description="Isolates the browsing context from cross-origin windows to mitigate side-channel attacks.",
    why_it_matters="Helps protect against Spectre-style attacks and cross-window reference leaks (tabnabbing).",
    recommended_value="same-origin",
    owasp_reference="https://owasp.org/www-project-secure-headers/#cross-origin-opener-policy",
    mozilla_recommendation="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
    microsoft_recommendation="Set to 'same-origin' unless cross-origin popups are required.",
    example_secure_config="Cross-Origin-Opener-Policy: same-origin",
))

_add(HeaderDefinition(
    name="Cross-Origin-Embedder-Policy",
    category="Cross-Origin Isolation",
    security_relevant=True,
    missing_severity=Severity.LOW,
    description="Requires explicit opt-in from cross-origin resources before they can be embedded.",
    why_it_matters="Enables full cross-origin isolation (needed for SharedArrayBuffer) and blocks "
                   "loading of resources that don't grant permission.",
    recommended_value="require-corp or credentialless",
    owasp_reference="https://owasp.org/www-project-secure-headers/#cross-origin-embedder-policy",
    mozilla_recommendation="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
    microsoft_recommendation="Enable when cross-origin isolation is required.",
    example_secure_config="Cross-Origin-Embedder-Policy: require-corp",
))

_add(HeaderDefinition(
    name="Cross-Origin-Resource-Policy",
    category="Cross-Origin Isolation",
    security_relevant=True,
    missing_severity=Severity.LOW,
    description="Restricts which origins can embed/load this resource.",
    why_it_matters="Mitigates speculative side-channel attacks (Spectre) and unwanted cross-origin embedding.",
    recommended_value="same-origin or same-site",
    owasp_reference="https://owasp.org/www-project-secure-headers/#cross-origin-resource-policy",
    mozilla_recommendation="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
    microsoft_recommendation="Set to 'same-site' for most APIs.",
    example_secure_config="Cross-Origin-Resource-Policy: same-origin",
))

_add(HeaderDefinition(
    name="Origin-Agent-Cluster",
    category="Process Isolation",
    security_relevant=True,
    missing_severity=Severity.INFO,
    description="Requests the browser place the origin in its own agent cluster (separate process).",
    why_it_matters="Improves isolation guarantees and can mitigate certain side-channel/timing attacks.",
    recommended_value="?1",
    mozilla_recommendation="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin-Agent-Cluster",
    example_secure_config="Origin-Agent-Cluster: ?1",
))

_add(HeaderDefinition(
    name="Content-Type",
    category="MIME Security",
    security_relevant=True,
    missing_severity=Severity.MEDIUM,
    description="Declares the MIME type of the returned content.",
    why_it_matters="Missing/incorrect Content-Type can lead to MIME-sniffing based XSS.",
    recommended_value="Accurate MIME type with charset, e.g. text/html; charset=UTF-8",
    mozilla_recommendation="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type",
    example_secure_config="Content-Type: text/html; charset=UTF-8",
))

_add(HeaderDefinition(
    name="Cache-Control",
    category="Caching",
    security_relevant=True,
    missing_severity=Severity.LOW,
    description="Directs caching behavior of browsers and intermediate proxies.",
    why_it_matters="Improper caching of sensitive pages (login, account data) can leak information "
                   "via shared caches or browser history.",
    recommended_value="no-store (for sensitive pages) or appropriate max-age for static assets",
    mozilla_recommendation="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
    example_secure_config="Cache-Control: no-store, max-age=0",
))

_add(HeaderDefinition(
    name="Pragma",
    category="Caching",
    security_relevant=False,
    missing_severity=Severity.INFO,
    description="Legacy HTTP/1.0 caching directive.",
    why_it_matters="Superseded by Cache-Control; only relevant for backward compatibility.",
    recommended_value="no-cache (legacy compatibility only)",
    deprecated=True,
    example_secure_config="Pragma: no-cache",
))

_add(HeaderDefinition(
    name="Expires",
    category="Caching",
    security_relevant=False,
    missing_severity=Severity.INFO,
    description="Legacy header specifying an absolute expiration date for cached content.",
    why_it_matters="Superseded by Cache-Control max-age but still honored by some caches.",
    recommended_value="Set appropriately or rely on Cache-Control",
    deprecated=True,
))

_add(HeaderDefinition(
    name="Feature-Policy",
    category="Feature Control",
    security_relevant=True,
    missing_severity=Severity.INFO,
    description="Legacy predecessor to Permissions-Policy.",
    why_it_matters="Deprecated; modern browsers use Permissions-Policy instead.",
    recommended_value="Replace with Permissions-Policy",
    deprecated=True,
))

_add(HeaderDefinition(
    name="Expect-CT",
    category="Certificate Transparency",
    security_relevant=True,
    missing_severity=Severity.INFO,
    description="Historically enforced Certificate Transparency compliance.",
    why_it_matters="Deprecated by browsers (Chrome removed support); CT enforcement is now automatic.",
    recommended_value="No longer required in modern browsers",
    deprecated=True,
))

_add(HeaderDefinition(
    name="NEL",
    category="Monitoring",
    security_relevant=False,
    missing_severity=Severity.INFO,
    description="Network Error Logging - instructs browsers to report network errors.",
    why_it_matters="Purely operational/monitoring; not a direct security control.",
    recommended_value="Configure alongside Report-To for network diagnostics.",
))

_add(HeaderDefinition(
    name="Report-To",
    category="Monitoring",
    security_relevant=False,
    missing_severity=Severity.INFO,
    description="Configures endpoints for browser reporting API (CSP violations, NEL, etc.).",
    why_it_matters="Useful for detecting attacks/misconfigurations in production via automated reports.",
    recommended_value="Configure a reporting endpoint for CSP/NEL/Deprecation reports.",
))

_add(HeaderDefinition(
    name="Timing-Allow-Origin",
    category="Cross-Origin",
    security_relevant=True,
    missing_severity=Severity.INFO,
    description="Allows cross-origin sites to see fine-grained resource timing data.",
    why_it_matters="Overly permissive values can leak timing information used for side-channel attacks.",
    recommended_value="Restrict to trusted origins only, avoid '*' on sensitive resources.",
))

_add(HeaderDefinition(
    name="Access-Control-Allow-Origin",
    category="CORS",
    security_relevant=True,
    missing_severity=Severity.INFO,
    description="Declares which origins may read cross-origin responses (CORS).",
    why_it_matters="A wildcard '*' combined with credentials, or reflecting the Origin header "
                   "unconditionally, can expose sensitive data to any website.",
    recommended_value="Explicit trusted origin list; never '*' with credentials enabled.",
    owasp_reference="https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
    example_secure_config="Access-Control-Allow-Origin: https://trusted-app.example.com",
    weak_values=["*"],
))

_add(HeaderDefinition(
    name="Access-Control-Allow-Credentials",
    category="CORS",
    security_relevant=True,
    missing_severity=Severity.INFO,
    description="Indicates whether the response can be shared with credentialed requests.",
    why_it_matters="Combined with a permissive Access-Control-Allow-Origin, this can allow "
                   "cross-site theft of authenticated data.",
    recommended_value="true only when Allow-Origin is a specific, trusted domain.",
))

_add(HeaderDefinition(
    name="Access-Control-Allow-Headers",
    category="CORS",
    security_relevant=False,
    missing_severity=Severity.INFO,
    description="Lists headers allowed in a cross-origin request.",
    why_it_matters="Overly broad wildcard allowances widen the CORS attack surface.",
    recommended_value="Explicit list of required headers only.",
))

_add(HeaderDefinition(
    name="Access-Control-Allow-Methods",
    category="CORS",
    security_relevant=False,
    missing_severity=Severity.INFO,
    description="Lists HTTP methods allowed for cross-origin requests.",
    why_it_matters="Should be limited to methods actually required by legitimate clients.",
    recommended_value="Explicit list, e.g. GET, POST",
))

_add(HeaderDefinition(
    name="Access-Control-Expose-Headers",
    category="CORS",
    security_relevant=False,
    missing_severity=Severity.INFO,
    description="Lists response headers exposed to cross-origin JavaScript.",
    why_it_matters="Avoid exposing sensitive internal headers to untrusted origins.",
    recommended_value="Minimal necessary set of headers.",
))

_add(HeaderDefinition(
    name="Server",
    category="Information Disclosure",
    security_relevant=True,
    missing_severity=Severity.INFO,
    description="Identifies the web server software (and often version).",
    why_it_matters="Detailed version banners help attackers fingerprint known CVEs for that exact "
                   "software version.",
    recommended_value="Remove or generalize (e.g. just 'nginx' without version number).",
    example_secure_config="Server: nginx",
))

_add(HeaderDefinition(
    name="Via",
    category="Information Disclosure",
    security_relevant=False,
    missing_severity=Severity.INFO,
    description="Reveals intermediate proxies/gateways the request passed through.",
    why_it_matters="Can leak internal infrastructure details.",
    recommended_value="Strip on public-facing responses where possible.",
))

_add(HeaderDefinition(
    name="X-Powered-By",
    category="Information Disclosure",
    security_relevant=True,
    missing_severity=Severity.LOW,
    description="Reveals the backend framework/language (e.g. PHP, Express, ASP.NET).",
    why_it_matters="Directly aids attackers in selecting framework-specific exploits.",
    recommended_value="Remove this header entirely.",
    example_secure_config="(header removed)",
))

_add(HeaderDefinition(
    name="X-AspNet-Version",
    category="Information Disclosure",
    security_relevant=True,
    missing_severity=Severity.LOW,
    description="Reveals the exact ASP.NET framework version in use.",
    why_it_matters="Enables precise version-targeted exploitation.",
    recommended_value="Disable via <httpRuntime enableVersionHeader=\"false\"/>",
))

_add(HeaderDefinition(
    name="X-Runtime",
    category="Information Disclosure",
    security_relevant=False,
    missing_severity=Severity.INFO,
    description="Commonly used by Ruby on Rails to show request processing time.",
    why_it_matters="Minor information disclosure; also can aid timing-based enumeration.",
    recommended_value="Remove in production.",
))

_add(HeaderDefinition(
    name="X-Generator",
    category="Information Disclosure",
    security_relevant=True,
    missing_severity=Severity.INFO,
    description="Reveals the CMS/framework that generated the page (common in Drupal).",
    why_it_matters="Aids attackers in fingerprinting the CMS and targeting known vulnerabilities.",
    recommended_value="Remove in production.",
))

_add(HeaderDefinition(
    name="Alt-Svc",
    category="Protocol",
    security_relevant=False,
    missing_severity=Severity.INFO,
    description="Advertises alternative protocols/services (e.g. HTTP/3 / QUIC endpoint).",
    why_it_matters="Operational header; not a direct vulnerability but reveals HTTP/3 support.",
    recommended_value="Configure to advertise HTTP/3 if supported.",
))

_add(HeaderDefinition(
    name="Accept-CH",
    category="Client Hints",
    security_relevant=True,
    missing_severity=Severity.INFO,
    description="Requests specific Client Hints from the browser.",
    why_it_matters="Overly broad client hints requests can increase fingerprinting surface / privacy risk.",
    recommended_value="Request only the client hints actually needed.",
))

_add(HeaderDefinition(
    name="Accept-CH-Lifetime",
    category="Client Hints",
    security_relevant=False,
    missing_severity=Severity.INFO,
    description="Deprecated header specifying how long client hint preferences persist.",
    why_it_matters="Removed from the spec/browsers; no longer effective.",
    recommended_value="Removed from modern browsers; no action needed.",
    deprecated=True,
))

_add(HeaderDefinition(
    name="X-Permitted-Cross-Domain-Policies",
    category="Legacy Cross-Domain",
    security_relevant=True,
    missing_severity=Severity.LOW,
    description="Controls whether Adobe Flash/PDF clients may load cross-domain policy files.",
    why_it_matters="Prevents legacy Flash/PDF-based cross-domain data theft.",
    recommended_value="none",
    example_secure_config="X-Permitted-Cross-Domain-Policies: none",
))

_add(HeaderDefinition(
    name="Clear-Site-Data",
    category="Session Security",
    security_relevant=True,
    missing_severity=Severity.INFO,
    description="Instructs the browser to clear cookies/storage/cache for the origin.",
    why_it_matters="Useful on logout endpoints to fully clear session artifacts client-side.",
    recommended_value='"cache","cookies","storage" on logout responses',
    example_secure_config='Clear-Site-Data: "cache","cookies","storage"',
))

_add(HeaderDefinition(
    name="ETag", category="Caching", security_relevant=False, missing_severity=Severity.INFO,
    description="Entity tag used for cache validation.",
    why_it_matters="Can leak inode/file information on some servers if not randomized; low risk.",
    recommended_value="Use weak ETags or hash-based values, avoid inode-based ones.",
))

_add(HeaderDefinition(
    name="Last-Modified", category="Caching", security_relevant=False, missing_severity=Severity.INFO,
    description="Indicates when the resource was last modified.",
    why_it_matters="Rarely sensitive; supports conditional GET caching.",
    recommended_value="Set accurately for cacheable resources.",
))

_add(HeaderDefinition(
    name="Date", category="General", security_relevant=False, missing_severity=Severity.INFO,
    description="Server-generated timestamp of the response.",
    why_it_matters="Standard HTTP header; no direct security implication.",
    recommended_value="N/A",
))

_add(HeaderDefinition(
    name="Transfer-Encoding", category="Protocol", security_relevant=True, missing_severity=Severity.INFO,
    description="Specifies encoding used to transfer the body (e.g. chunked).",
    why_it_matters="Mismatched Transfer-Encoding/Content-Length handling can enable HTTP Request "
                   "Smuggling between front-end and back-end servers.",
    recommended_value="Ensure consistent handling across proxies (no smuggling ambiguity).",
))

_add(HeaderDefinition(
    name="Connection", category="Protocol", security_relevant=False, missing_severity=Severity.INFO,
    description="Controls whether the network connection stays open after the transaction.",
    why_it_matters="Operational; generally not a security concern.",
    recommended_value="N/A",
))

_add(HeaderDefinition(
    name="Vary", category="Caching", security_relevant=True, missing_severity=Severity.INFO,
    description="Tells caches which request headers affect the response representation.",
    why_it_matters="Missing 'Vary: Cookie' (or Authorization) on personalized responses behind shared "
                   "caches can lead to cache poisoning / cross-user data leakage.",
    recommended_value="Include Cookie/Authorization when responses are personalized.",
))

_add(HeaderDefinition(
    name="Content-Encoding", category="General", security_relevant=True, missing_severity=Severity.INFO,
    description="Indicates compression applied to the body (gzip, br, etc.).",
    why_it_matters="Compression combined with reflected secrets can enable BREACH-style attacks over TLS.",
    recommended_value="Disable compression for pages that mix secrets with attacker-controlled input.",
))

_add(HeaderDefinition(
    name="Content-Length", category="General", security_relevant=False, missing_severity=Severity.INFO,
    description="Declares the size of the response body in bytes.",
    why_it_matters="Standard header; smuggling concerns arise mainly when combined with Transfer-Encoding.",
    recommended_value="N/A",
))

_add(HeaderDefinition(
    name="Upgrade", category="Protocol", security_relevant=False, missing_severity=Severity.INFO,
    description="Used to negotiate switching protocols (e.g. to WebSocket, HTTP/2).",
    why_it_matters="Operational; ensure only intended protocol upgrades are permitted.",
    recommended_value="N/A",
))

_add(HeaderDefinition(
    name="Allow", category="General", security_relevant=True, missing_severity=Severity.INFO,
    description="Lists HTTP methods supported by the resource (typically on 405 responses).",
    why_it_matters="Can reveal unnecessarily enabled methods (e.g. TRACE, PUT) widening attack surface.",
    recommended_value="Disable unused/dangerous methods (TRACE, PUT, DELETE) unless required.",
))

_add(HeaderDefinition(
    name="Location", category="Redirection", security_relevant=True, missing_severity=Severity.INFO,
    description="Target URL for redirects (3xx responses).",
    why_it_matters="Unvalidated redirect targets can enable open-redirect phishing attacks.",
    recommended_value="Validate against an allow-list before redirecting.",
))

_add(HeaderDefinition(
    name="Refresh", category="Redirection", security_relevant=True, missing_severity=Severity.INFO,
    description="Meta-refresh style redirect delivered via HTTP header.",
    why_it_matters="Like Location, can be abused for open-redirect / phishing if user-controlled.",
    recommended_value="Avoid; use standard 3xx redirects with validated targets instead.",
))

_add(HeaderDefinition(
    name="Link", category="General", security_relevant=False, missing_severity=Severity.INFO,
    description="Used for resource hints (preload, preconnect) or pagination.",
    why_it_matters="Generally low risk; verify linked origins are trusted.",
    recommended_value="N/A",
))

_add(HeaderDefinition(
    name="Server-Timing", category="Monitoring", security_relevant=False, missing_severity=Severity.INFO,
    description="Exposes backend performance metrics to the browser.",
    why_it_matters="Can leak internal architecture/timing details useful for reconnaissance.",
    recommended_value="Limit to non-sensitive timing metrics in production.",
))

_add(HeaderDefinition(
    name="Set-Cookie", category="Session Security", security_relevant=True, missing_severity=Severity.INFO,
    description="Sets a cookie on the client; analyzed in detail by the Cookie Security module.",
    why_it_matters="See Cookie Security Analysis tab for full detail.",
    recommended_value="Secure; HttpOnly; SameSite=Strict/Lax",
))


def get_definition(header_name: str) -> Optional[HeaderDefinition]:
    return HEADER_DB.get(header_name.lower())


def all_security_headers() -> list[str]:
    """Ordered list of headers actively evaluated as part of the core checklist."""
    return [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-XSS-Protection",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Resource-Policy",
        "Origin-Agent-Cluster",
        "Content-Type",
        "Cache-Control",
    ]


def all_informational_headers() -> list[str]:
    """Headers displayed/analyzed but not counted as hard failures in the score."""
    return [
        "Pragma", "Expires", "Feature-Policy", "Expect-CT", "NEL", "Report-To",
        "Timing-Allow-Origin", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
        "Access-Control-Allow-Headers", "Access-Control-Allow-Methods",
        "Access-Control-Expose-Headers", "Server", "Via", "X-Powered-By",
        "X-AspNet-Version", "X-Runtime", "X-Generator", "Alt-Svc", "Accept-CH",
        "Accept-CH-Lifetime", "X-Permitted-Cross-Domain-Policies", "Clear-Site-Data",
        "ETag", "Last-Modified", "Date", "Transfer-Encoding", "Connection", "Vary",
        "Content-Encoding", "Content-Length", "Upgrade", "Allow", "Location", "Refresh",
        "Link", "Server-Timing",
    ]
