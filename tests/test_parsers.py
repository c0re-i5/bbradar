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
