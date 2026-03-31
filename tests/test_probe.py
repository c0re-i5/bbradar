"""
Tests for the probe module — recon data analysis and follow-up tool suggestions.
"""

import pytest

from bbradar.modules.probe import (
    get_target_intel,
    suggest_actions,
    PORT_ACTIONS,
    SERVICE_ACTIONS,
    TECH_ACTIONS,
)
from bbradar.modules.recon import add_recon, bulk_add_recon
from bbradar.modules.projects import create_project
from bbradar.modules.targets import add_target


@pytest.fixture
def project_with_target(tmp_db):
    """Create a project and target for probe tests."""
    pid = create_project("Probe Test Project", db_path=tmp_db)
    tid = add_target(pid, "domain", "example.com", db_path=tmp_db)
    return pid, tid, tmp_db


class TestGetTargetIntel:
    def test_empty_target(self, project_with_target):
        pid, tid, db = project_with_target
        intel = get_target_intel(tid, db_path=db)
        assert intel["target_id"] == tid
        assert intel["ports"] == []
        assert intel["services"] == []
        assert intel["tech"] == []

    def test_ports_parsed(self, project_with_target):
        pid, tid, db = project_with_target
        add_recon(tid, "port", "80/tcp", source_tool="nmap", db_path=db)
        add_recon(tid, "port", "443/tcp", source_tool="nmap", db_path=db)
        intel = get_target_intel(tid, db_path=db)
        ports = [p["port"] for p in intel["ports"]]
        assert 80 in ports
        assert 443 in ports
        assert len(intel["ports"]) == 2

    def test_services_parsed(self, project_with_target):
        pid, tid, db = project_with_target
        add_recon(tid, "port", "80/tcp", source_tool="nmap", db_path=db)
        add_recon(tid, "service", "80:http", source_tool="nmap", db_path=db)
        intel = get_target_intel(tid, db_path=db)
        assert len(intel["services"]) == 1
        assert intel["services"][0]["name"] == "http"
        # Port entry should have service name filled in
        assert intel["ports"][0]["service"] == "http"

    def test_tech_gathered(self, project_with_target):
        pid, tid, db = project_with_target
        add_recon(tid, "tech", "Apache 2.4.52", source_tool="whatweb", db_path=db)
        add_recon(tid, "tech", "WordPress 6.4", source_tool="whatweb", db_path=db)
        intel = get_target_intel(tid, db_path=db)
        assert len(intel["tech"]) == 2

    def test_subdomains_gathered(self, project_with_target):
        pid, tid, db = project_with_target
        bulk_add_recon(tid, "subdomain", ["a.example.com", "b.example.com"],
                       source_tool="subfinder", db_path=db)
        intel = get_target_intel(tid, db_path=db)
        assert len(intel["subdomains"]) == 2

    def test_mixed_data(self, project_with_target):
        pid, tid, db = project_with_target
        add_recon(tid, "port", "80/tcp", source_tool="nmap", db_path=db)
        add_recon(tid, "url", "http://example.com", source_tool="httpx", db_path=db)
        add_recon(tid, "endpoint", "/admin", source_tool="gobuster", db_path=db)
        add_recon(tid, "dns", "A:93.184.216.34", source_tool="dig", db_path=db)
        intel = get_target_intel(tid, db_path=db)
        assert len(intel["ports"]) == 1
        assert len(intel["urls"]) == 1
        assert len(intel["endpoints"]) == 1
        assert len(intel["dns"]) == 1


class TestSuggestActions:
    def _make_intel(self, ports=None, services=None, tech=None):
        return {
            "target_id": 1,
            "ports": ports or [],
            "services": services or [],
            "tech": tech or [],
            "subdomains": [],
            "urls": [],
            "endpoints": [],
            "dns": [],
        }

    def test_http_port_suggestions(self):
        intel = self._make_intel(ports=[{"port": 80, "proto": "tcp", "service": ""}])
        suggestions = suggest_actions(intel)
        tool_names = [s["tool"] for s in suggestions]
        assert "nikto" in tool_names
        assert "nuclei" in tool_names
        assert "gobuster" in tool_names
        assert "whatweb" in tool_names

    def test_https_port_suggestions(self):
        intel = self._make_intel(ports=[{"port": 443, "proto": "tcp", "service": ""}])
        suggestions = suggest_actions(intel)
        tool_names = [s["tool"] for s in suggestions]
        assert "testssl" in tool_names

    def test_ssh_port_suggestions(self):
        intel = self._make_intel(ports=[{"port": 22, "proto": "tcp", "service": ""}])
        suggestions = suggest_actions(intel)
        assert len(suggestions) >= 1
        assert suggestions[0]["tool"] == "nmap"

    def test_ftp_port_suggestions(self):
        intel = self._make_intel(ports=[{"port": 21, "proto": "tcp", "service": ""}])
        suggestions = suggest_actions(intel)
        assert len(suggestions) >= 1

    def test_port_filter(self):
        intel = self._make_intel(ports=[
            {"port": 80, "proto": "tcp", "service": ""},
            {"port": 443, "proto": "tcp", "service": ""},
        ])
        suggestions = suggest_actions(intel, port_filter=80)
        # Should only have suggestions for port 80
        for s in suggestions:
            if s.get("port"):
                assert s["port"] == 80

    def test_service_suggestions(self):
        intel = self._make_intel(
            services=[{"port": 3306, "name": "mysql"}],
        )
        suggestions = suggest_actions(intel)
        tool_names = [s["tool"] for s in suggestions]
        assert "nmap" in tool_names

    def test_tech_wordpress_suggestions(self):
        intel = self._make_intel(tech=["WordPress 6.4"])
        suggestions = suggest_actions(intel)
        tool_names = [s["tool"] for s in suggestions]
        assert "wpscan" in tool_names

    def test_tech_jenkins_suggestions(self):
        intel = self._make_intel(tech=["Jenkins 2.440"])
        suggestions = suggest_actions(intel)
        tool_names = [s["tool"] for s in suggestions]
        assert "nuclei" in tool_names

    def test_no_duplicates(self):
        # Port 80 and http service should not produce duplicate nikto suggestions
        intel = self._make_intel(
            ports=[{"port": 80, "proto": "tcp", "service": "http"}],
            services=[{"port": 80, "name": "http"}],
        )
        suggestions = suggest_actions(intel)
        # Count nikto suggestions for port 80
        nikto_80 = [s for s in suggestions if s["tool"] == "nikto" and s.get("port") == 80]
        assert len(nikto_80) == 1

    def test_empty_intel_no_suggestions(self):
        intel = self._make_intel()
        suggestions = suggest_actions(intel)
        assert suggestions == []

    def test_suggestions_numbered(self):
        intel = self._make_intel(ports=[{"port": 80, "proto": "tcp", "service": ""}])
        suggestions = suggest_actions(intel)
        indices = [s["index"] for s in suggestions]
        assert indices == list(range(1, len(suggestions) + 1))

    def test_multiple_ports_combined(self):
        intel = self._make_intel(ports=[
            {"port": 22, "proto": "tcp", "service": ""},
            {"port": 80, "proto": "tcp", "service": ""},
            {"port": 443, "proto": "tcp", "service": ""},
        ])
        suggestions = suggest_actions(intel)
        # Should have suggestions for all three ports
        ports_with_suggestions = set(s.get("port") for s in suggestions if s.get("port"))
        assert 22 in ports_with_suggestions
        assert 80 in ports_with_suggestions
        assert 443 in ports_with_suggestions


class TestPortActionsRegistry:
    def test_common_ports_covered(self):
        """Verify common ports have action mappings."""
        expected_ports = [21, 22, 80, 443, 445, 3306, 8080]
        for port in expected_ports:
            assert port in PORT_ACTIONS, f"Port {port} not in PORT_ACTIONS"

    def test_all_tools_in_runners(self):
        """All suggested tools must exist in TOOL_RUNNERS."""
        from bbradar.modules.recon import TOOL_RUNNERS
        for port, actions in PORT_ACTIONS.items():
            for tool_name, desc, args in actions:
                assert tool_name in TOOL_RUNNERS, \
                    f"Tool '{tool_name}' for port {port} not in TOOL_RUNNERS"

    def test_service_tools_in_runners(self):
        from bbradar.modules.recon import TOOL_RUNNERS
        for svc, actions in SERVICE_ACTIONS.items():
            for tool_name, desc, args in actions:
                assert tool_name in TOOL_RUNNERS, \
                    f"Tool '{tool_name}' for service '{svc}' not in TOOL_RUNNERS"

    def test_tech_tools_in_runners(self):
        from bbradar.modules.recon import TOOL_RUNNERS
        for tech, actions in TECH_ACTIONS.items():
            for tool_name, desc, args in actions:
                assert tool_name in TOOL_RUNNERS, \
                    f"Tool '{tool_name}' for tech '{tech}' not in TOOL_RUNNERS"
