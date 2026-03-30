"""
Tests for input validation utilities and normalization.
"""

import pytest

from bbradar.core.utils import (
    validate_domain, validate_ip, validate_cidr, validate_url,
    validate_target_value, validate_cvss_vector, normalize_cwe,
)


class TestValidateDomain:
    def test_valid_domain(self):
        assert validate_domain("example.com") is None

    def test_valid_subdomain(self):
        assert validate_domain("sub.example.com") is None

    def test_valid_wildcard(self):
        assert validate_domain("*.example.com") is None

    def test_empty_domain(self):
        assert validate_domain("") is not None

    def test_too_long_domain(self):
        assert validate_domain("a" * 254) is not None

    def test_empty_label(self):
        assert validate_domain("example..com") is not None

    def test_label_too_long(self):
        assert validate_domain("a" * 64 + ".com") is not None

    def test_invalid_chars(self):
        assert validate_domain("exam ple.com") is not None

    def test_hyphen_middle_ok(self):
        assert validate_domain("my-site.example.com") is None

    def test_hyphen_start_invalid(self):
        assert validate_domain("-example.com") is not None


class TestValidateIP:
    def test_valid_ipv4(self):
        assert validate_ip("192.168.1.1") is None

    def test_valid_ipv6(self):
        assert validate_ip("::1") is None

    def test_invalid_ip(self):
        assert validate_ip("999.999.999.999") is not None

    def test_not_an_ip(self):
        assert validate_ip("example.com") is not None


class TestValidateCIDR:
    def test_valid_cidr4(self):
        assert validate_cidr("10.0.0.0/24") is None

    def test_valid_cidr6(self):
        assert validate_cidr("2001:db8::/32") is None

    def test_invalid_cidr(self):
        assert validate_cidr("not-a-cidr") is not None

    def test_single_ip_as_cidr(self):
        assert validate_cidr("10.0.0.1/32") is None


class TestValidateURL:
    def test_valid_https(self):
        assert validate_url("https://example.com/api") is None

    def test_valid_http(self):
        assert validate_url("http://example.com") is None

    def test_empty_url(self):
        assert validate_url("") is not None

    def test_invalid_scheme(self):
        assert validate_url("ftp://example.com") is not None

    def test_no_host(self):
        assert validate_url("https://") is not None


class TestValidateTargetValue:
    def test_domain(self):
        assert validate_target_value("example.com", "domain") is None

    def test_invalid_domain(self):
        assert validate_target_value("not valid!", "domain") is not None

    def test_ip(self):
        assert validate_target_value("10.0.0.1", "ip") is None

    def test_cidr(self):
        assert validate_target_value("10.0.0.0/24", "cidr") is None

    def test_url(self):
        assert validate_target_value("https://example.com", "url") is None

    def test_other_type_no_validation(self):
        # 'other' and 'mobile_app' types skip validation
        assert validate_target_value("anything goes", "other") is None
        assert validate_target_value("com.app.test", "mobile_app") is None

    def test_empty_value(self):
        assert validate_target_value("", "domain") is not None
        assert validate_target_value("   ", "domain") is not None


class TestValidateCVSSVector:
    def test_valid_v31(self):
        assert validate_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") is None

    def test_valid_v30(self):
        assert validate_cvss_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None

    def test_empty(self):
        assert validate_cvss_vector("") is None
        assert validate_cvss_vector(None) is None

    def test_invalid_format(self):
        assert validate_cvss_vector("not-a-vector") is not None

    def test_v2_format_rejected(self):
        assert validate_cvss_vector("AV:N/AC:L/Au:N/C:C/I:C/A:C") is not None

    def test_invalid_metric_value(self):
        assert validate_cvss_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") is not None


class TestNormalizeCWE:
    def test_standard_format(self):
        assert normalize_cwe("CWE-79") == "CWE-79"

    def test_lowercase(self):
        assert normalize_cwe("cwe-79") == "CWE-79"

    def test_no_hyphen(self):
        assert normalize_cwe("CWE79") == "CWE-79"

    def test_number_only(self):
        assert normalize_cwe("79") == "CWE-79"

    def test_empty(self):
        assert normalize_cwe("") == ""

    def test_none(self):
        assert normalize_cwe(None) is None

    def test_invalid_nonnumeric(self):
        # Returns None for unparseable input
        assert normalize_cwe("not-a-cwe") is None
