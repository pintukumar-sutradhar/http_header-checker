"""Tests for passive technology fingerprinting."""
from header_checker.core.fingerprint import fingerprint_server


class TestServerDetection:
    def test_nginx_banner(self):
        fp = fingerprint_server({"server": "nginx/1.24.0"})
        assert fp.web_server == "Nginx"
        assert fp.server_banner == "nginx/1.24.0"

    def test_apache_banner(self):
        fp = fingerprint_server({"server": "Apache/2.4.57 (Debian)"})
        assert fp.web_server == "Apache HTTP Server"
        assert fp.operating_system == "Debian Linux"


class TestCdnDetection:
    def test_cloudflare_via_header(self):
        fp = fingerprint_server({"cf-ray": "abc123"})
        assert fp.cdn == "Cloudflare"

    def test_cloudfront(self):
        fp = fingerprint_server({"x-amz-cf-id": "xyz"})
        assert fp.cdn == "Amazon CloudFront"
        assert "AWS" in fp.technologies


class TestFrameworkDetection:
    def test_php_powered_by(self):
        fp = fingerprint_server({"x-powered-by": "PHP/8.2.0"})
        assert fp.framework == "PHP"

    def test_aspnet_version_header(self):
        fp = fingerprint_server({"x-aspnet-version": "4.0.30319"})
        assert fp.framework == "ASP.NET"


class TestCmsDetection:
    def test_wordpress_cookie(self):
        fp = fingerprint_server({}, cookies_raw=["wordpress_test_cookie=1"])
        assert fp.cms == "WordPress"

    def test_body_hints(self):
        fp = fingerprint_server({}, body_snippet="<link rel='stylesheet' href='/wp-content/theme.css'>")
        assert fp.cms == "WordPress"


class TestTechnologiesList:
    def test_sorted_and_deduplicated(self):
        fp = fingerprint_server(
            {"server": "cloudflare", "cf-ray": "x", "via": "1.1 proxy"}
        )
        assert fp.technologies == sorted(set(fp.technologies))
