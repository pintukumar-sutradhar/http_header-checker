"""
scanner/tls_scanner.py
========================
Performs a direct TLS handshake against the target host (independent of the
``requests``/urllib3 layer) to extract detailed certificate and cipher
information: protocol version, cipher suite, certificate chain details,
SAN list, SHA-256 fingerprint, public key size, expiry, self-signed / weak
crypto detection, and basic HSTS preload eligibility heuristics.
"""
from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

from utils.constants import WEAK_TLS_VERSIONS, WEAK_CIPHER_KEYWORDS
from utils.models import TLSAnalysis, Finding, Severity
from utils.logger import get_logger

logger = get_logger()

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    _HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTOGRAPHY = False


def _parse_certificate_der(der_bytes: bytes, hostname: str) -> dict:
    """Extract rich certificate details using the `cryptography` library."""
    info: dict = {}
    if not _HAS_CRYPTOGRAPHY:
        return info

    cert = x509.load_der_x509_certificate(der_bytes, default_backend())

    info["subject"] = cert.subject.rfc4514_string()
    info["issuer"] = cert.issuer.rfc4514_string()
    info["not_before"] = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
    info["not_after"] = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
    info["is_self_signed"] = (cert.issuer == cert.subject)
    info["sha256_fingerprint"] = cert.fingerprint(hashes.SHA256()).hex(":").upper()

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        info["san_list"] = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        info["san_list"] = []

    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        info["public_key_type"] = "RSA"
        info["public_key_size"] = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        info["public_key_type"] = "EC (" + pub_key.curve.name + ")"
        info["public_key_size"] = pub_key.key_size
    else:
        info["public_key_type"] = type(pub_key).__name__
        info["public_key_size"] = None

    try:
        aia_ext = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        ocsp_urls = [
            desc.access_location.value
            for desc in aia_ext.value
            if desc.access_method == x509.AuthorityInformationAccessOID.OCSP
        ]
        info["ocsp_urls"] = ocsp_urls
    except x509.ExtensionNotFound:
        info["ocsp_urls"] = []

    # Hostname match check (basic wildcard support)
    hostname_matches = False
    candidates = info.get("san_list") or []
    for candidate in candidates:
        pattern = candidate.lower()
        if pattern == hostname.lower():
            hostname_matches = True
            break
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if hostname.lower().endswith(suffix):
                hostname_matches = True
                break
    info["hostname_mismatch"] = not hostname_matches and bool(candidates)

    return info


def analyze_tls(hostname: str, port: int = 443, timeout: int = 10) -> TLSAnalysis:
    """Open a raw TLS socket to the target and extract handshake + certificate info."""
    analysis = TLSAnalysis()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # we want to inspect even invalid/self-signed certs

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                analysis.supported = True
                analysis.tls_version = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    analysis.cipher_suite = cipher[0]
                    analysis.cipher_bits = cipher[2]

                der_cert = ssock.getpeercert(binary_form=True)
                if der_cert:
                    details = _parse_certificate_der(der_cert, hostname)
                    analysis.certificate_subject = details.get("subject")
                    analysis.certificate_issuer = details.get("issuer")
                    analysis.san_list = details.get("san_list", [])
                    analysis.sha256_fingerprint = details.get("sha256_fingerprint")
                    analysis.public_key_size = details.get("public_key_size")
                    analysis.public_key_type = details.get("public_key_type")
                    analysis.is_self_signed = details.get("is_self_signed", False)
                    analysis.hostname_mismatch = details.get("hostname_mismatch", False)
                    analysis.ocsp_urls = details.get("ocsp_urls", [])

                    not_after = details.get("not_after")
                    not_before = details.get("not_before")
                    if not_after:
                        if not_after.tzinfo is None:
                            not_after = not_after.replace(tzinfo=timezone.utc)
                        analysis.certificate_expiry = not_after.strftime("%Y-%m-%d %H:%M:%S UTC")
                        days_left = (not_after - datetime.now(timezone.utc)).days
                        analysis.days_until_expiry = days_left
                        analysis.is_expired = days_left < 0
                    if not_before:
                        if not_before.tzinfo is None:
                            not_before = not_before.replace(tzinfo=timezone.utc)
                        analysis.certificate_not_before = not_before.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Weak protocol / cipher detection
        if analysis.tls_version in WEAK_TLS_VERSIONS:
            analysis.weak_protocol = True
            analysis.issues.append(f"Weak/deprecated TLS protocol negotiated: {analysis.tls_version}")

        if analysis.cipher_suite and any(k in analysis.cipher_suite for k in WEAK_CIPHER_KEYWORDS):
            analysis.weak_cipher = True
            analysis.issues.append(f"Weak cipher suite negotiated: {analysis.cipher_suite}")

        if analysis.is_self_signed:
            analysis.issues.append("Certificate is self-signed.")
        if analysis.is_expired:
            analysis.issues.append("Certificate has EXPIRED.")
        elif analysis.days_until_expiry is not None and analysis.days_until_expiry < 30:
            analysis.issues.append(f"Certificate expires soon ({analysis.days_until_expiry} days remaining).")
        if analysis.hostname_mismatch:
            analysis.issues.append("Certificate hostname/SAN does not match the target hostname.")
        if analysis.public_key_size and analysis.public_key_type == "RSA" and analysis.public_key_size < 2048:
            analysis.issues.append(f"RSA public key size is weak: {analysis.public_key_size} bits (< 2048).")

        # Heuristic HSTS preload eligibility (protocol-level only; full check requires HSTS header + subdomains)
        analysis.hsts_preload_eligible = (
            analysis.supported and not analysis.weak_protocol and not analysis.is_expired
            and not analysis.is_self_signed and not analysis.hostname_mismatch
        )

    except ssl.SSLCertVerificationError as exc:
        analysis.error = f"Certificate verification error: {exc}"
        analysis.issues.append(analysis.error)
    except (socket.timeout, TimeoutError):
        analysis.error = "TLS connection timed out."
        analysis.issues.append(analysis.error)
    except (ConnectionRefusedError, OSError) as exc:
        analysis.error = f"Could not establish TLS connection: {exc}"
        analysis.issues.append(analysis.error)
    except Exception as exc:  # pragma: no cover - defensive catch-all
        logger.exception("Unexpected TLS analysis error")
        analysis.error = f"Unexpected TLS error: {exc}"
        analysis.issues.append(analysis.error)

    return analysis


def tls_findings(analysis: TLSAnalysis) -> list[Finding]:
    findings: list[Finding] = []
    if not analysis.supported:
        if analysis.error:
            findings.append(Finding(
                title="TLS connection could not be established",
                severity=Severity.MEDIUM,
                description=analysis.error,
                business_impact="Unable to verify transport security posture of the target.",
                remediation="Verify the target supports TLS on the expected port and is reachable.",
                category="Transport Security",
            ))
        return findings

    if analysis.weak_protocol:
        findings.append(Finding(
            title=f"Weak TLS protocol version negotiated ({analysis.tls_version})",
            severity=Severity.CRITICAL,
            description="The server accepted a connection using an outdated/insecure TLS protocol.",
            business_impact="Outdated protocols are vulnerable to known cryptographic attacks "
                             "(e.g. POODLE, BEAST) and may not meet compliance requirements (PCI-DSS).",
            remediation="Disable SSLv2/SSLv3/TLS 1.0/TLS 1.1; support only TLS 1.2 and TLS 1.3.",
            references=["https://owasp.org/www-project-top-ten/"],
            category="Transport Security",
        ))
    if analysis.weak_cipher:
        findings.append(Finding(
            title=f"Weak cipher suite negotiated ({analysis.cipher_suite})",
            severity=Severity.HIGH,
            description="A cryptographically weak cipher suite was accepted by the server.",
            business_impact="Weak ciphers can be broken to decrypt intercepted traffic.",
            remediation="Restrict server cipher suite configuration to strong, modern AEAD ciphers.",
            category="Transport Security",
        ))
    if analysis.is_expired:
        findings.append(Finding(
            title="TLS certificate has expired",
            severity=Severity.CRITICAL,
            description=f"Certificate expired on {analysis.certificate_expiry}.",
            business_impact="Browsers will show hard security warnings; users may abandon the site "
                             "or be trained to click through TLS warnings, increasing MITM risk.",
            remediation="Renew the TLS certificate immediately and automate renewal (e.g. ACME/Let's Encrypt).",
            category="Certificate Management",
        ))
    elif analysis.days_until_expiry is not None and 0 <= analysis.days_until_expiry < 30:
        findings.append(Finding(
            title="TLS certificate expiring soon",
            severity=Severity.MEDIUM,
            description=f"Certificate expires in {analysis.days_until_expiry} day(s) "
                        f"({analysis.certificate_expiry}).",
            business_impact="Service disruption and trust warnings if certificate lapses.",
            remediation="Renew the certificate before expiry and verify auto-renewal automation.",
            category="Certificate Management",
        ))
    if analysis.is_self_signed:
        findings.append(Finding(
            title="Self-signed TLS certificate in use",
            severity=Severity.HIGH,
            description="The certificate is not issued by a trusted public Certificate Authority.",
            business_impact="Browsers will display trust warnings; unsuitable for production/public sites.",
            remediation="Obtain a certificate from a trusted CA (e.g. Let's Encrypt, DigiCert).",
            category="Certificate Management",
        ))
    if analysis.hostname_mismatch:
        findings.append(Finding(
            title="TLS certificate hostname mismatch",
            severity=Severity.HIGH,
            description="The certificate's Subject Alternative Names do not include the scanned hostname.",
            business_impact="Browsers will show hostname mismatch warnings; also indicates possible "
                             "misconfiguration or MITM.",
            remediation="Issue a certificate that correctly covers the target hostname (and SANs).",
            category="Certificate Management",
        ))
    if analysis.public_key_type == "RSA" and analysis.public_key_size and analysis.public_key_size < 2048:
        findings.append(Finding(
            title="Weak RSA public key size",
            severity=Severity.HIGH,
            description=f"RSA key size is only {analysis.public_key_size} bits.",
            business_impact="Keys under 2048 bits are considered crackable with modern compute resources.",
            remediation="Reissue the certificate with a minimum 2048-bit (ideally 3072/4096-bit) RSA key, "
                        "or migrate to ECDSA.",
            category="Certificate Management",
        ))
    return findings
