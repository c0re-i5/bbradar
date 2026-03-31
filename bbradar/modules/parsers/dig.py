"""
dig output parser.

Handles dig text output and parses DNS record types
(A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR).
"""

from . import register_parser, make_finding

TOOL_NAME = "dig"

# Record types that may have security implications
_SECURITY_RECORDS = {
    "TXT": {
        "v=spf": ("informational", "SPF record found — email sender validation configured"),
        "v=dmarc": ("informational", "DMARC record found — email authentication policy configured"),
        "v=dkim": ("informational", "DKIM record found — email signing configured"),
    },
    "MX": ("informational", "Mail exchange server discovered"),
    "NS": ("informational", "Nameserver discovered"),
    "CNAME": ("informational", "CNAME record — potential subdomain takeover if dangling"),
    "SRV": ("informational", "Service record discovered"),
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse dig output into findings."""
    findings = []

    stripped = data.strip()
    if not stripped:
        return findings

    # Parse dig output sections
    current_query = ""
    in_answer = False

    for line in stripped.splitlines():
        line = line.strip()

        # Track which query domain we're looking at
        if line.startswith(";; QUESTION SECTION:"):
            in_answer = False
            continue
        if line.startswith(";; ANSWER SECTION:"):
            in_answer = True
            continue
        if line.startswith(";; AUTHORITY SECTION:"):
            # Authority section also has useful records
            in_answer = True
            continue
        if line.startswith(";; ADDITIONAL SECTION:"):
            in_answer = True
            continue
        if line.startswith(";;") or line.startswith(";"):
            # Comment or other section header
            if "QUERY:" in line or "opcode:" in line:
                in_answer = False
            continue
        if not line or line.startswith(";;"):
            continue

        # If we're not in query section, try to extract query name
        if not in_answer:
            # Question section format: ;name.    IN  A
            if line.startswith(";"):
                parts = line.lstrip(";").split()
                if parts:
                    current_query = parts[0].rstrip(".")
            continue

        # Answer/Authority/Additional section record parsing
        # Format: name TTL class type value
        parts = line.split()
        if len(parts) < 5:
            # Short format possible: name type value
            if len(parts) >= 3:
                name = parts[0].rstrip(".")
                record_type = parts[-2].upper()
                record_value = parts[-1].rstrip(".")
            else:
                continue
        else:
            name = parts[0].rstrip(".")
            record_type = parts[3].upper() if len(parts) > 3 else ""
            record_value = " ".join(parts[4:]).rstrip(".")
            if not record_type:
                continue

        if not current_query:
            current_query = name

        severity = "informational"
        description = f"DNS {record_type} record for {name}: {record_value}"

        # Check for security-relevant records
        if record_type == "TXT":
            for pattern, (sev, desc) in _SECURITY_RECORDS.get("TXT", {}).items():
                if pattern in record_value.lower():
                    severity = sev
                    description += f"\n{desc}"
                    break
        elif record_type == "CNAME":
            # Flag potential subdomain takeover indicators
            dangling_services = [
                "amazonaws.com", "azurewebsites.net", "cloudfront.net",
                "herokuapp.com", "github.io", "shopify.com",
                "pantheon.io", "zendesk.com", "surge.sh",
                "ghost.io", "bitbucket.io",
            ]
            for service in dangling_services:
                if service in record_value.lower():
                    severity = "low"
                    description += (
                        f"\nCNAME points to {service} — verify this is not a dangling record "
                        f"(potential subdomain takeover)"
                    )
                    break

        findings.append(make_finding(
            tool=TOOL_NAME,
            title=f"DNS {record_type}: {name} → {record_value[:60]}",
            severity=severity,
            vuln_type="info_disclosure",
            description=description,
            endpoint=name,
            host=current_query or name,
            evidence=line,
            tags=["dns", "dig", record_type.lower()],
        ))

    return findings


register_parser(TOOL_NAME, __import__(__name__, fromlist=[""]))
