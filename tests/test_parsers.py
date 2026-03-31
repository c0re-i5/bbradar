"""
Tests for tool output parsers.
"""

import json
import textwrap

import pytest

from bbradar.modules.parsers import (
    make_finding,
    _normalize_severity,
    _make_fingerprint,
    detect_tool,
    list_parsers,
    get_parser,
)


# ===================================================================
# Core parser utilities
# ===================================================================

class TestMakeFinding:
    def test_minimal(self):
        f = make_finding(tool="test", title="Test Finding")
        assert f["tool"] == "test"
        assert f["title"] == "Test Finding"
        assert f["severity"] == "informational"
        assert f["fingerprint"]  # auto-generated

    def test_all_fields(self):
        f = make_finding(
            tool="nuclei", title="XSS Found", severity="high",
            vuln_type="xss", description="Reflected XSS",
            endpoint="https://example.com/search", host="example.com",
            port=443, evidence="<script>alert(1)</script>",
            cve_id="CVE-2024-1234", cwe_id="CWE-79",
            cvss_score=8.1, references=["https://ref.example.com"],
            tags=["xss", "reflected"], raw_data={"custom": "data"},
        )
        assert f["severity"] == "high"
        assert f["vuln_type"] == "xss"
        assert f["port"] == 443
        assert f["cvss_score"] == 8.1
        assert len(f["references"]) == 1
        assert f["tags"] == ["xss", "reflected"]

    def test_custom_fingerprint_preserved(self):
        f = make_finding(tool="test", title="Test", fingerprint="custom123")
        assert f["fingerprint"] == "custom123"

    def test_defaults_for_lists(self):
        f = make_finding(tool="test", title="Test")
        assert f["references"] == []
        assert f["tags"] == []
        assert f["raw_data"] == {}


class TestNormalizeSeverity:
    @pytest.mark.parametrize("inp,expected", [
        ("critical", "critical"), ("crit", "critical"),
        ("high", "high"), ("h", "high"),
        ("medium", "medium"), ("med", "medium"), ("moderate", "medium"),
        ("low", "low"), ("l", "low"),
        ("informational", "informational"), ("info", "informational"),
        ("none", "informational"), ("unknown", "informational"),
    ])
    def test_known_severities(self, inp, expected):
        assert _normalize_severity(inp) == expected

    def test_case_insensitive(self):
        assert _normalize_severity("HIGH") == "high"
        assert _normalize_severity("Critical") == "critical"

    def test_empty(self):
        assert _normalize_severity("") == "informational"
        assert _normalize_severity(None) == "informational"

    def test_unknown_defaults_to_info(self):
        assert _normalize_severity("bogus") == "informational"


class TestMakeFingerprint:
    def test_deterministic(self):
        f = make_finding(tool="test", title="T", host="h", port=80, endpoint="/x")
        f2 = make_finding(tool="test", title="T", host="h", port=80, endpoint="/x")
        assert f["fingerprint"] == f2["fingerprint"]

    def test_different_input_different_fingerprint(self):
        f1 = make_finding(tool="test", title="A", host="h1")
        f2 = make_finding(tool="test", title="B", host="h2")
        assert f1["fingerprint"] != f2["fingerprint"]


# ===================================================================
# Parser registry
# ===================================================================

class TestParserRegistry:
    def test_list_parsers_has_nuclei_and_nmap(self):
        names = list_parsers()
        assert "nuclei" in names
        assert "nmap" in names
        assert len(names) >= 10

    def test_get_parser_returns_module(self):
        p = get_parser("nuclei")
        assert p is not None
        assert hasattr(p, "parse")

    def test_get_parser_unknown(self):
        assert get_parser("nonexistent_tool") is None


# ===================================================================
# Tool detection
# ===================================================================

class TestDetectTool:
    def test_hint(self):
        assert detect_tool(hint="nuclei") == "nuclei"
        assert detect_tool(hint="NMAP") == "nmap"

    def test_filename_nuclei(self):
        assert detect_tool(filepath="scan_nuclei_output.jsonl") == "nuclei"

    def test_filename_nmap(self):
        assert detect_tool(filepath="nmap_results.xml") == "nmap"

    def test_content_nuclei(self):
        data = json.dumps({"template-id": "cve-2024-1234", "info": {}, "matched-at": "http://x"})
        assert detect_tool(data=data) == "nuclei"

    def test_content_nmap(self):
        data = '<nmaprun scanner="nmap"><host></host></nmaprun>'
        assert detect_tool(data=data) == "nmap"

    def test_no_match(self):
        assert detect_tool(data="just some random text") is None


# ===================================================================
# Nuclei parser
# ===================================================================

class TestNucleiParser:
    SAMPLE_FINDING = {
        "template-id": "cve-2024-9999",
        "info": {
            "name": "Test Vuln",
            "severity": "high",
            "description": "A test vulnerability",
            "tags": "xss,cve",
            "classification": {
                "cve-id": ["CVE-2024-9999"],
                "cwe-id": ["CWE-79"],
                "cvss-score": 8.1,
            },
            "reference": ["https://ref.example.com"],
        },
        "matched-at": "https://example.com/vuln",
        "host": "https://example.com",
        "request": "GET /vuln HTTP/1.1",
        "response": "HTTP/1.1 200 OK",
    }

    def _parse(self, data):
        p = get_parser("nuclei")
        if isinstance(data, (dict, list)):
            data = json.dumps(data)
        return p.parse(data)

    def test_single_json(self):
        findings = self._parse(self.SAMPLE_FINDING)
        assert len(findings) == 1
        f = findings[0]
        assert f["tool"] == "nuclei"
        assert f["severity"] == "high"
        assert f["vuln_type"] == "xss"
        assert f["cve_id"] == "CVE-2024-9999"
        assert f["cwe_id"] == "CWE-79"

    def test_jsonl_format(self):
        lines = "\n".join(json.dumps(self.SAMPLE_FINDING) for _ in range(3))
        findings = self._parse(lines)
        assert len(findings) == 3

    def test_json_array(self):
        arr = [self.SAMPLE_FINDING, self.SAMPLE_FINDING]
        findings = self._parse(json.dumps(arr))
        assert len(findings) == 2

    def test_empty_input(self):
        findings = self._parse("")
        assert findings == []

    def test_invalid_json(self):
        findings = self._parse("not json at all")
        assert findings == []

    def test_missing_template_id_skipped(self):
        obj = {"info": {"name": "No template"}, "host": "x"}
        findings = self._parse(obj)
        assert findings == []

    def test_severity_mapping(self):
        obj = dict(self.SAMPLE_FINDING)
        obj["info"] = dict(obj["info"])
        obj["info"]["severity"] = "info"
        findings = self._parse(obj)
        assert findings[0]["severity"] == "informational"

    def test_tag_to_vuln_type_mapping(self):
        obj = dict(self.SAMPLE_FINDING)
        obj["info"] = dict(obj["info"])
        obj["info"]["tags"] = "sqli,injection"
        findings = self._parse(obj)
        assert findings[0]["vuln_type"] == "sqli"


# ===================================================================
# Nmap parser
# ===================================================================

class TestNmapParser:
    SAMPLE_XML = textwrap.dedent("""\
        <?xml version="1.0" encoding="UTF-8"?>
        <nmaprun scanner="nmap" args="nmap -sV 10.0.0.1" start="1700000000">
          <host starttime="1700000000" endtime="1700000001">
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <hostnames>
              <hostname name="target.example.com" type="PTR"/>
            </hostnames>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="nginx" version="1.25.3"/>
              </port>
              <port protocol="tcp" portid="443">
                <state state="open"/>
                <service name="https" product="nginx" version="1.25.3"/>
              </port>
              <port protocol="tcp" portid="22">
                <state state="closed"/>
                <service name="ssh"/>
              </port>
            </ports>
          </host>
        </nmaprun>
    """)

    def _parse(self, data):
        p = get_parser("nmap")
        return p.parse(data)

    def test_basic_parse(self):
        findings = self._parse(self.SAMPLE_XML)
        # Should find open ports (80, 443), not closed (22)
        open_port_findings = [f for f in findings if f["title"].startswith("Open Port")]
        assert len(open_port_findings) == 2

    def test_host_extracted(self):
        findings = self._parse(self.SAMPLE_XML)
        assert all(f["host"] == "target.example.com" for f in findings)

    def test_port_extracted(self):
        findings = self._parse(self.SAMPLE_XML)
        ports = [f["port"] for f in findings if f.get("port")]
        assert 80 in ports
        assert 443 in ports

    def test_service_info_in_title(self):
        findings = self._parse(self.SAMPLE_XML)
        titles = [f["title"] for f in findings]
        assert any("nginx" in t for t in titles)

    def test_invalid_xml(self):
        findings = self._parse("not xml")
        assert findings == []

    def test_empty_xml(self):
        findings = self._parse('<nmaprun scanner="nmap"></nmaprun>')
        assert findings == []

    def test_insecure_service_detection(self):
        xml = textwrap.dedent("""\
            <?xml version="1.0"?>
            <nmaprun scanner="nmap">
              <host>
                <address addr="10.0.0.1" addrtype="ipv4"/>
                <ports>
                  <port protocol="tcp" portid="21">
                    <state state="open"/>
                    <service name="ftp"/>
                  </port>
                  <port protocol="tcp" portid="23">
                    <state state="open"/>
                    <service name="telnet"/>
                  </port>
                </ports>
              </host>
            </nmaprun>
        """)
        findings = self._parse(xml)
        titles = " ".join(f["title"] for f in findings)
        # Should have at least the open port findings, and possibly insecure service
        assert "21" in titles
        assert "23" in titles


# ===================================================================
# Masscan parser
# ===================================================================

class TestMasscanParser:
    def _parse(self, data):
        p = get_parser("masscan")
        return p.parse(data)

    def test_json_format(self):
        data = json.dumps([
            {"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open", "service": {"name": "http"}}]},
            {"ip": "10.0.0.1", "ports": [{"port": 443, "proto": "tcp", "status": "open", "service": {"name": "https"}}]},
        ])
        findings = self._parse(data)
        assert len(findings) == 2
        assert findings[0]["tool"] == "masscan"
        assert findings[0]["port"] == 80
        assert findings[1]["port"] == 443

    def test_list_format(self):
        data = "open tcp 22 10.0.0.1 1700000000\nopen tcp 80 10.0.0.1 1700000001\n"
        findings = self._parse(data)
        assert len(findings) == 2
        assert findings[0]["port"] == 22
        assert findings[1]["port"] == 80

    def test_closed_ports_skipped(self):
        data = json.dumps([
            {"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "closed"}]},
        ])
        findings = self._parse(data)
        assert len(findings) == 0

    def test_empty_input(self):
        findings = self._parse("")
        assert findings == []

    def test_comments_skipped(self):
        data = "# masscan output\nopen tcp 80 10.0.0.1 1700000000\n"
        findings = self._parse(data)
        assert len(findings) == 1


# ===================================================================
# Gobuster parser
# ===================================================================

class TestGobusterParser:
    def _parse(self, data):
        p = get_parser("gobuster")
        return p.parse(data)

    def test_text_format(self):
        data = "/admin (Status: 200) [Size: 1234]\n/backup (Status: 403) [Size: 567]\n"
        findings = self._parse(data)
        assert len(findings) == 2
        assert "/admin" in findings[0]["title"]
        assert "200" in findings[0]["title"]

    def test_jsonl_format(self):
        lines = "\n".join([
            json.dumps({"url": "/api", "status": 200, "length": 500}),
            json.dumps({"url": "/admin", "status": 401, "length": 100}),
        ])
        findings = self._parse(lines)
        assert len(findings) == 2

    def test_401_is_medium(self):
        data = json.dumps({"url": "/admin", "status": 401, "length": 0})
        findings = self._parse(data)
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"

    def test_404_filtered(self):
        data = json.dumps({"url": "/missing", "status": 404, "length": 0})
        findings = self._parse(data)
        assert len(findings) == 0

    def test_empty(self):
        assert self._parse("") == []

    def test_gobuster_banner_skipped(self):
        data = "Gobuster v3.6\n===============\nStarting gobuster...\n/admin (Status: 200) [Size: 1234]\nFinished\n"
        findings = self._parse(data)
        assert len(findings) == 1


# ===================================================================
# WhatWeb parser
# ===================================================================

class TestWhatWebParser:
    def _parse(self, data):
        p = get_parser("whatweb")
        return p.parse(data)

    def test_json_format(self):
        data = json.dumps([{
            "target": "http://example.com",
            "http_status": 200,
            "plugins": {
                "Apache": {"version": ["2.4.52"]},
                "PHP": {"version": ["8.1.2"]},
                "WordPress": {"version": ["6.4"]},
            },
        }])
        findings = self._parse(data)
        # Should have summary + security concern findings
        assert len(findings) >= 1
        tools = [f["tool"] for f in findings]
        assert all(t == "whatweb" for t in tools)

    def test_security_concerns_flagged(self):
        data = json.dumps([{
            "target": "http://example.com",
            "http_status": 200,
            "plugins": {
                "Jenkins": {"version": ["2.440"]},
                "phpMyAdmin": {},
            },
        }])
        findings = self._parse(data)
        severities = [f["severity"] for f in findings]
        assert "medium" in severities  # Jenkins and phpMyAdmin are medium

    def test_text_format(self):
        data = "http://example.com [200 OK] Apache[2.4.52], PHP[8.1.2], WordPress"
        findings = self._parse(data)
        assert len(findings) >= 1
        assert "example.com" in findings[0]["endpoint"]

    def test_empty(self):
        assert self._parse("") == []


# ===================================================================
# Amass parser
# ===================================================================

class TestAmassParser:
    def _parse(self, data):
        p = get_parser("amass")
        return p.parse(data)

    def test_jsonl_format(self):
        lines = "\n".join([
            json.dumps({"name": "sub1.example.com", "domain": "example.com", "addresses": [{"ip": "10.0.0.1"}]}),
            json.dumps({"name": "sub2.example.com", "domain": "example.com", "addresses": [{"ip": "10.0.0.2"}]}),
        ])
        findings = self._parse(lines)
        assert len(findings) == 2
        assert findings[0]["host"] == "sub1.example.com"
        assert "Subdomain" in findings[0]["title"]

    def test_text_format(self):
        data = "sub1.example.com\nsub2.example.com\nsub3.example.com\n"
        findings = self._parse(data)
        assert len(findings) == 3

    def test_dedup(self):
        data = "sub1.example.com\nsub1.example.com\n"
        findings = self._parse(data)
        assert len(findings) == 1

    def test_banner_skipped(self):
        data = "OWASP Amass v4.0\n---\nQuerying data sources\nsub1.example.com\n"
        findings = self._parse(data)
        assert len(findings) == 1
        assert findings[0]["host"] == "sub1.example.com"

    def test_empty(self):
        assert self._parse("") == []


# ===================================================================
# Dig parser
# ===================================================================

class TestDigParser:
    def _parse(self, data):
        p = get_parser("dig")
        return p.parse(data)

    def test_answer_section(self):
        data = textwrap.dedent("""\
            ;; QUESTION SECTION:
            ;example.com.			IN	A

            ;; ANSWER SECTION:
            example.com.		300	IN	A	93.184.216.34
            example.com.		300	IN	A	93.184.216.35
        """)
        findings = self._parse(data)
        assert len(findings) == 2
        assert findings[0]["tool"] == "dig"
        assert "A" in findings[0]["title"]

    def test_cname_subdomain_takeover(self):
        data = textwrap.dedent("""\
            ;; ANSWER SECTION:
            sub.example.com.	300	IN	CNAME	app.herokuapp.com.
        """)
        findings = self._parse(data)
        assert len(findings) == 1
        assert findings[0]["severity"] == "low"
        assert "subdomain takeover" in findings[0]["description"]

    def test_txt_spf_record(self):
        data = textwrap.dedent("""\
            ;; ANSWER SECTION:
            example.com.		300	IN	TXT	"v=spf1 include:_spf.google.com ~all"
        """)
        findings = self._parse(data)
        assert len(findings) == 1
        assert "SPF" in findings[0]["description"]

    def test_mx_record(self):
        data = textwrap.dedent("""\
            ;; ANSWER SECTION:
            example.com.		300	IN	MX	10 mail.example.com.
        """)
        findings = self._parse(data)
        assert len(findings) == 1
        assert "MX" in findings[0]["title"]

    def test_empty(self):
        assert self._parse("") == []

    def test_comments_only(self):
        data = ";; Query time: 20 msec\n;; SERVER: 8.8.8.8#53(8.8.8.8)\n"
        findings = self._parse(data)
        assert findings == []
