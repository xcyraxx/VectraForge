"""
tests/test_parser.py — HTTP Parser Unit Tests
===============================================
Tests the HTTPRequestParser against a variety of real-world request formats.
Run with: pytest tests/ -v
"""

import pytest
from core.parser import HTTPRequestParser


@pytest.fixture
def parser():
    return HTTPRequestParser()


class TestBasicParsing:

    def test_simple_get(self, parser):
        raw = "GET /index.html HTTP/1.1\nHost: example.com\n\n"
        r = parser.parse(raw)
        assert r.method == "GET"
        assert r.path == "/index.html"
        assert r.host == "example.com"
        assert r.url == "http://example.com/index.html"

    def test_post_with_form_body(self, parser):
        raw = (
            "POST /login HTTP/1.1\n"
            "Host: app.local\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "\n"
            "username=admin&password=secret"
        )
        r = parser.parse(raw)
        assert r.method == "POST"
        assert r.body_params.get("username") == ["admin"]
        assert r.body_params.get("password") == ["secret"]

    def test_query_parameters(self, parser):
        raw = "GET /search?q=test&page=1&page=2 HTTP/1.1\nHost: example.com\n\n"
        r = parser.parse(raw)
        assert r.query_params.get("q") == ["test"]
        assert r.query_params.get("page") == ["1", "2"]  # Multi-value

    def test_cookies(self, parser):
        raw = (
            "GET / HTTP/1.1\n"
            "Host: example.com\n"
            "Cookie: session=abc123; user=john; theme=dark\n\n"
        )
        r = parser.parse(raw)
        assert r.cookies.get("session") == "abc123"
        assert r.cookies.get("user") == "john"

    def test_json_body(self, parser):
        raw = (
            'POST /api/user HTTP/1.1\n'
            'Host: api.example.com\n'
            'Content-Type: application/json\n'
            '\n'
            '{"id": 42, "action": "delete"}'
        )
        r = parser.parse(raw)
        assert r.json_body == {"id": 42, "action": "delete"}
        assert r.body_params.get("id") == ["42"]

    def test_https_flag(self, parser):
        raw = "GET /secure HTTP/1.1\nHost: bank.com\n\n"
        r = parser.parse(raw, is_https=True)
        assert r.url.startswith("https://")
        assert r.is_https is True

    def test_crlf_line_endings(self, parser):
        raw = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        r = parser.parse(raw)
        assert r.method == "GET"
        assert r.host == "example.com"

    def test_malformed_request_line_raises(self, parser):
        with pytest.raises(ValueError):
            parser.parse("NOTVALID\n\n")

    def test_target_host_fallback(self, parser):
        raw = "GET /page HTTP/1.1\n\n"
        r = parser.parse(raw, target_host="fallback.com")
        assert r.host == "fallback.com"

    def test_xml_body_detected(self, parser):
        raw = (
            "POST /xml-api HTTP/1.1\n"
            "Host: example.com\n"
            "Content-Type: text/xml\n"
            "\n"
            "<?xml version='1.0'?><root><item>test</item></root>"
        )
        r = parser.parse(raw)
        assert r.xml_body is not None
        assert "<root>" in r.xml_body


class TestSQLiTargets:
    """Ensure parameters useful for SQLi testing are captured correctly."""

    def test_sqli_parameter_in_query(self, parser):
        raw = "GET /item?id=1' OR '1'='1 HTTP/1.1\nHost: vuln.app\n\n"
        r = parser.parse(raw)
        assert "id" in r.query_params

    def test_sqli_parameter_in_body(self, parser):
        raw = (
            "POST /login HTTP/1.1\n"
            "Host: vuln.app\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "\n"
            "user=admin'--&pass=x"
        )
        r = parser.parse(raw)
        assert "user" in r.body_params


class TestEdgeCases:

    def test_empty_body(self, parser):
        raw = "DELETE /resource/5 HTTP/1.1\nHost: api.com\n\n"
        r = parser.parse(raw)
        assert r.body is None

    def test_no_content_type(self, parser):
        raw = "POST /endpoint HTTP/1.1\nHost: api.com\n\nraw body data"
        r = parser.parse(raw)
        assert r.body == "raw body data"

    def test_authorization_header_present(self, parser):
        raw = (
            "GET /admin HTTP/1.1\n"
            "Host: admin.com\n"
            "Authorization: Bearer eyJhbGc.eyJzdWI.signature\n\n"
        )
        r = parser.parse(raw)
        assert "authorization" in r.headers
