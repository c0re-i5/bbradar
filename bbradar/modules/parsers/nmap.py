"""
Nmap output parser.

Handles Nmap XML output (-oX).  Extracts open ports, service versions,
OS detection, and NSE script findings.
"""

import xml.etree.ElementTree as ET
from . import register_parser, make_finding

TOOL_NAME = "nmap"

# NSE scripts that indicate actual vulnerabilities
_VULN_SCRIPTS = {
    "ssl-heartbleed": ("critical", "known_cve", "CVE-2014-0160", "CWE-119"),
    "ssl-poodle": ("high", "known_cve", "CVE-2014-3566", "CWE-310"),
    "ssl-ccs-injection": ("high", "known_cve", "CVE-2014-0224", "CWE-310"),
    "http-shellshock": ("critical", "rce", "CVE-2014-6271", "CWE-78"),
    "smb-vuln-ms17-010": ("critical", "rce", "CVE-2017-0144", "CWE-20"),
    "smb-vuln-ms08-067": ("critical", "rce", "CVE-2008-4250", "CWE-94"),
    "http-sql-injection": ("high", "sqli", "", "CWE-89"),
    "http-stored-xss": ("high", "xss", "", "CWE-79"),
    "http-dombased-xss": ("medium", "xss", "", "CWE-79"),
    "http-phpself-xss": ("medium", "xss", "", "CWE-79"),
    "http-csrf": ("medium", "csrf", "", "CWE-352"),
    "http-vuln-cve*": ("high", "known_cve", "", ""),
    "vuln-cve*": ("high", "known_cve", "", ""),
}

# Known insecure services
_INSECURE_SERVICES = {
    "ftp": (21, "low", "Cleartext FTP service detected — credentials transmitted unencrypted"),
    "telnet": (23, "medium", "Telnet service detected — credentials transmitted unencrypted"),
    "smtp": (25, "low", "SMTP service detected — check for open relay"),
    "snmp": (161, "medium", "SNMP service detected — check community strings"),
    "rsh": (514, "high", "RSH service detected — unauthenticated remote shell"),
    "rlogin": (513, "high", "Rlogin service detected — weak authentication"),
    "rexec": (512, "high", "Rexec service detected — weak authentication"),
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse nmap XML output into findings."""
    findings = []

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return findings

    for host_el in root.findall(".//host"):
        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        host_ip = addr_el.get("addr", "")

        # Get hostname if available
        hostname = ""
        for hn in host_el.findall(".//hostname"):
            hostname = hn.get("name", "")
            if hostname:
                break

        host_str = hostname or host_ip

        # OS detection
        for osmatch in host_el.findall(".//osmatch"):
            os_name = osmatch.get("name", "")
            accuracy = osmatch.get("accuracy", "")
            if os_name:
                findings.append(make_finding(
                    tool=TOOL_NAME,
                    title=f"OS Detection: {os_name}",
                    severity="informational",
                    vuln_type="info_disclosure",
                    description=f"Operating system identified: {os_name} (accuracy: {accuracy}%)",
                    host=host_str,
                    evidence=f"OS: {os_name}\nAccuracy: {accuracy}%",
                    tags=["os-detection"],
                ))
                break  # Only report best match

        # Ports and services
        for port_el in host_el.findall(".//port"):
            protocol = port_el.get("protocol", "tcp")
            portid = port_el.get("portid", "")
            try:
                port_num = int(portid)
            except ValueError:
                continue

            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            service_el = port_el.find("service")
            svc_name = service_el.get("name", "") if service_el is not None else ""
            svc_product = service_el.get("product", "") if service_el is not None else ""
            svc_version = service_el.get("version", "") if service_el is not None else ""
            svc_extra = service_el.get("extrainfo", "") if service_el is not None else ""

            svc_desc = svc_name
            if svc_product:
                svc_desc = f"{svc_product} {svc_version}".strip()

            endpoint = f"{host_str}:{port_num}"

            # Service discovery finding
            findings.append(make_finding(
                tool=TOOL_NAME,
                title=f"Open Port: {port_num}/{protocol} ({svc_desc})",
                severity="informational",
                vuln_type="info_disclosure",
                description=(
                    f"Open port {port_num}/{protocol} on {host_str}.\n"
                    f"Service: {svc_name}\n"
                    f"Product: {svc_product} {svc_version}\n"
                    f"Extra: {svc_extra}" if svc_extra else
                    f"Open port {port_num}/{protocol} on {host_str}.\n"
                    f"Service: {svc_name}\n"
                    f"Product: {svc_product} {svc_version}"
                ),
                endpoint=endpoint,
                host=host_str,
                port=port_num,
                evidence=f"{port_num}/{protocol} open {svc_desc}",
                tags=["port-scan", svc_name] if svc_name else ["port-scan"],
            ))

            # Check for insecure services
            if svc_name in _INSECURE_SERVICES:
                _, sev, desc = _INSECURE_SERVICES[svc_name]
                findings.append(make_finding(
                    tool=TOOL_NAME,
                    title=f"Insecure Service: {svc_name.upper()} on {endpoint}",
                    severity=sev,
                    vuln_type="misconfiguration",
                    description=desc,
                    endpoint=endpoint,
                    host=host_str,
                    port=port_num,
                    tags=["insecure-service", svc_name],
                ))

            # NSE Script results
            for script_el in port_el.findall("script"):
                script_id = script_el.get("id", "")
                script_output = script_el.get("output", "")

                _parse_script(findings, script_id, script_output,
                              host_str, port_num, endpoint)

        # Host-level scripts
        hostscript = host_el.find("hostscript")
        if hostscript is not None:
            for script_el in hostscript.findall("script"):
                script_id = script_el.get("id", "")
                script_output = script_el.get("output", "")
                _parse_script(findings, script_id, script_output,
                              host_str, None, host_str)

    return findings


def _parse_script(findings: list, script_id: str, script_output: str,
                  host: str, port: int | None, endpoint: str):
    """Parse an NSE script result into a finding."""
    if not script_id or not script_output:
        return

    # Check known vuln scripts
    for pattern, (sev, vtype, cve, cwe) in _VULN_SCRIPTS.items():
        if pattern.endswith("*"):
            if script_id.startswith(pattern[:-1]):
                findings.append(make_finding(
                    tool=TOOL_NAME,
                    title=f"NSE: {script_id} on {endpoint}",
                    severity=sev,
                    vuln_type=vtype,
                    description=script_output[:1000],
                    endpoint=endpoint,
                    host=host,
                    port=port,
                    evidence=script_output[:2000],
                    cve_id=cve,
                    cwe_id=cwe,
                    tags=["nse", script_id],
                ))
                return
        elif script_id == pattern:
            findings.append(make_finding(
                tool=TOOL_NAME,
                title=f"NSE: {script_id} on {endpoint}",
                severity=sev,
                vuln_type=vtype,
                description=script_output[:1000],
                endpoint=endpoint,
                host=host,
                port=port,
                evidence=script_output[:2000],
                cve_id=cve,
                cwe_id=cwe,
                tags=["nse", script_id],
            ))
            return

    # VULNERABLE keyword detection
    if "VULNERABLE" in script_output.upper() or "State: VULNERABLE" in script_output:
        findings.append(make_finding(
            tool=TOOL_NAME,
            title=f"NSE Vulnerability: {script_id} on {endpoint}",
            severity="high",
            vuln_type="known_cve",
            description=f"NSE script {script_id} reported a vulnerability.",
            endpoint=endpoint,
            host=host,
            port=port,
            evidence=script_output[:2000],
            tags=["nse", "vuln", script_id],
        ))
    elif script_id.startswith("http-") or script_id.startswith("ssl-"):
        # Interesting web/SSL script results
        findings.append(make_finding(
            tool=TOOL_NAME,
            title=f"NSE: {script_id} on {endpoint}",
            severity="informational",
            vuln_type="info_disclosure",
            description=script_output[:500],
            endpoint=endpoint,
            host=host,
            port=port,
            evidence=script_output[:2000],
            tags=["nse", script_id],
        ))


register_parser(TOOL_NAME, __import__(__name__, fromlist=[""]))
