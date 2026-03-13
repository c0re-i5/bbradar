"""
Vulnerability Knowledge Base.

A reference library of common vulnerability types with standardized
descriptions, impact statements, remediation guidance, CWE/OWASP
references, and default CVSS scores. When logging a finding, pick
a template and only fill in the target-specific details.
"""

# Each entry has:
#   key:           short identifier used in CLI (e.g. "xss-reflected")
#   title:         default title template ({{target}} is replaced)
#   vuln_type:     maps to vulns table vuln_type
#   severity:      default severity
#   cvss_score:    default CVSS 3.1 base score
#   cvss_vector:   default CVSS 3.1 vector
#   cwe:           CWE identifier(s)
#   owasp:         OWASP Top 10 (2021) category
#   description:   standard description ({{target}}, {{parameter}}, {{endpoint}} substituted)
#   impact:        standard impact statement
#   remediation:   standard remediation guidance
#   references:    list of reference URLs

VULN_TEMPLATES: dict[str, dict] = {}

def _t(key, **kwargs):
    """Register a template."""
    kwargs["key"] = key
    VULN_TEMPLATES[key] = kwargs


# ═══════════════════════════════════════════════════════════════════
# Injection
# ═══════════════════════════════════════════════════════════════════

_t("xss-reflected",
   title="Reflected Cross-Site Scripting (XSS) on {{endpoint}}",
   vuln_type="xss",
   severity="high",
   cvss_score=6.1,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
   cwe="CWE-79",
   owasp="A03:2021 — Injection",
   description=(
       "The application reflects user-supplied input from the {{parameter}} parameter "
       "at {{endpoint}} into the HTTP response without proper output encoding. "
       "This allows an attacker to inject arbitrary HTML/JavaScript that executes "
       "in the context of the victim's browser session."
   ),
   impact=(
       "An attacker can craft a malicious URL that, when visited by a victim, "
       "executes arbitrary JavaScript in their browser. This can lead to session "
       "hijacking, credential theft, keylogging, phishing, and actions performed "
       "on behalf of the victim."
   ),
   remediation=(
       "1. Apply context-aware output encoding to all user-supplied input before "
       "rendering it in HTML, JavaScript, CSS, or URL contexts.\n"
       "2. Implement a strict Content Security Policy (CSP) header.\n"
       "3. Set the HttpOnly and Secure flags on session cookies.\n"
       "4. Consider using a templating engine that auto-escapes by default."
   ),
   references=[
       "https://owasp.org/www-community/attacks/xss/",
       "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
       "https://cwe.mitre.org/data/definitions/79.html",
   ],
)

_t("xss-stored",
   title="Stored Cross-Site Scripting (XSS) on {{endpoint}}",
   vuln_type="xss",
   severity="high",
   cvss_score=8.0,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N",
   cwe="CWE-79",
   owasp="A03:2021 — Injection",
   description=(
       "The application stores user-supplied input from {{parameter}} and renders "
       "it in pages served to other users without proper output encoding. The payload "
       "persists in the application (e.g., database, logs, comments) and fires every "
       "time an affected page is viewed."
   ),
   impact=(
       "Any user viewing the affected page will have the attacker's JavaScript "
       "execute in their browser. This enables mass session hijacking, worm-like "
       "propagation, persistent defacement, credential theft, and data exfiltration. "
       "Stored XSS typically has higher impact than reflected XSS because it does "
       "not require social engineering to trigger."
   ),
   remediation=(
       "1. Apply context-aware output encoding when rendering stored data.\n"
       "2. Sanitize input on the server side using an allowlist approach.\n"
       "3. Implement a strict Content Security Policy (CSP).\n"
       "4. Use HttpOnly and Secure cookie flags."
   ),
   references=[
       "https://owasp.org/www-community/attacks/xss/",
       "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
       "https://cwe.mitre.org/data/definitions/79.html",
   ],
)

_t("xss-dom",
   title="DOM-Based Cross-Site Scripting on {{endpoint}}",
   vuln_type="xss",
   severity="medium",
   cvss_score=6.1,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
   cwe="CWE-79",
   owasp="A03:2021 — Injection",
   description=(
       "The client-side JavaScript at {{endpoint}} reads user-controllable input "
       "from a DOM source (e.g., location.hash, document.URL) and passes it to "
       "a dangerous sink (e.g., innerHTML, eval, document.write) without sanitization."
   ),
   impact=(
       "An attacker can execute arbitrary JavaScript in the victim's browser by "
       "crafting a URL with a malicious fragment/parameter. Since the payload is "
       "processed entirely client-side, it may bypass server-side security controls."
   ),
   remediation=(
       "1. Avoid dangerous DOM sinks (innerHTML, eval, document.write).\n"
       "2. Use safe alternatives (textContent, createElement).\n"
       "3. Sanitize DOM sources with a library like DOMPurify.\n"
       "4. Implement a strict Content Security Policy (CSP)."
   ),
   references=[
       "https://owasp.org/www-community/attacks/DOM_Based_XSS",
       "https://cwe.mitre.org/data/definitions/79.html",
   ],
)

_t("sqli",
   title="SQL Injection on {{endpoint}}",
   vuln_type="sqli",
   severity="critical",
   cvss_score=9.8,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
   cwe="CWE-89",
   owasp="A03:2021 — Injection",
   description=(
       "The {{parameter}} parameter at {{endpoint}} is concatenated directly into "
       "a SQL query without parameterization or input validation. By injecting SQL "
       "syntax, an attacker can manipulate database queries to extract, modify, or "
       "delete data."
   ),
   impact=(
       "An attacker can read the entire database contents including user credentials "
       "and sensitive data, modify or delete records, and in some configurations "
       "achieve remote code execution on the database server. This can lead to "
       "complete compromise of the application and its data."
   ),
   remediation=(
       "1. Use parameterized queries (prepared statements) for all database access.\n"
       "2. Apply the principle of least privilege to database accounts.\n"
       "3. Implement input validation using an allowlist approach.\n"
       "4. Deploy a Web Application Firewall (WAF) as a defense-in-depth measure.\n"
       "5. Enable detailed error handling that does not expose SQL errors to users."
   ),
   references=[
       "https://owasp.org/www-community/attacks/SQL_Injection",
       "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
       "https://cwe.mitre.org/data/definitions/89.html",
   ],
)

_t("sqli-blind",
   title="Blind SQL Injection on {{endpoint}}",
   vuln_type="sqli",
   severity="critical",
   cvss_score=9.8,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
   cwe="CWE-89",
   owasp="A03:2021 — Injection",
   description=(
       "The {{parameter}} parameter at {{endpoint}} is vulnerable to blind SQL "
       "injection. While the application does not return SQL errors or query results "
       "directly, the attacker can infer information through boolean-based or "
       "time-based techniques."
   ),
   impact=(
       "Despite being blind, this vulnerability allows full database extraction "
       "through automated tools (e.g., sqlmap). The attacker can retrieve user "
       "credentials, PII, and other sensitive data, potentially leading to "
       "complete application compromise."
   ),
   remediation=(
       "1. Use parameterized queries (prepared statements) for all database access.\n"
       "2. Apply the principle of least privilege to database accounts.\n"
       "3. Implement input validation using an allowlist approach.\n"
       "4. Consider using an ORM that inherently prevents SQL injection."
   ),
   references=[
       "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
       "https://cwe.mitre.org/data/definitions/89.html",
   ],
)

_t("command-injection",
   title="OS Command Injection on {{endpoint}}",
   vuln_type="command_injection",
   severity="critical",
   cvss_score=9.8,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
   cwe="CWE-78",
   owasp="A03:2021 — Injection",
   description=(
       "The {{parameter}} parameter at {{endpoint}} is passed to an operating system "
       "command without proper sanitization. An attacker can inject shell metacharacters "
       "to execute arbitrary commands on the server."
   ),
   impact=(
       "An attacker can execute arbitrary operating system commands with the privileges "
       "of the web application. This typically leads to full server compromise, "
       "including data theft, lateral movement, persistence, and denial of service."
   ),
   remediation=(
       "1. Avoid calling OS commands directly; use language-native libraries instead.\n"
       "2. If OS commands are necessary, use parameterized APIs (e.g., subprocess with list args).\n"
       "3. Apply strict input validation with an allowlist of expected values.\n"
       "4. Run the application with minimal OS privileges."
   ),
   references=[
       "https://owasp.org/www-community/attacks/Command_Injection",
       "https://cwe.mitre.org/data/definitions/78.html",
   ],
)

_t("ssti",
   title="Server-Side Template Injection on {{endpoint}}",
   vuln_type="ssti",
   severity="critical",
   cvss_score=9.8,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
   cwe="CWE-1336",
   owasp="A03:2021 — Injection",
   description=(
       "User input from {{parameter}} is embedded into a server-side template "
       "at {{endpoint}} without sanitization. By injecting template directives, "
       "an attacker can execute arbitrary code on the server."
   ),
   impact=(
       "Server-side template injection typically leads to remote code execution (RCE). "
       "An attacker can read/write files, access environment variables and secrets, "
       "pivot to internal systems, and fully compromise the server."
   ),
   remediation=(
       "1. Never embed raw user input into templates.\n"
       "2. Use a sandboxed template engine or logic-less templates.\n"
       "3. Implement strict input validation.\n"
       "4. Run the application with minimal privileges."
   ),
   references=[
       "https://portswigger.net/web-security/server-side-template-injection",
       "https://cwe.mitre.org/data/definitions/1336.html",
   ],
)

# ═══════════════════════════════════════════════════════════════════
# Access Control
# ═══════════════════════════════════════════════════════════════════

_t("idor",
   title="Insecure Direct Object Reference (IDOR) on {{endpoint}}",
   vuln_type="idor",
   severity="high",
   cvss_score=7.5,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
   cwe="CWE-639",
   owasp="A01:2021 — Broken Access Control",
   description=(
       "The {{endpoint}} endpoint uses a user-controllable identifier ({{parameter}}) "
       "to access resources without verifying that the authenticated user is authorized "
       "to access the referenced object. By modifying this identifier, an attacker "
       "can access other users' data."
   ),
   impact=(
       "An attacker can access, modify, or delete data belonging to other users by "
       "manipulating object identifiers. Depending on the affected endpoint, this "
       "can lead to mass data extraction, unauthorized profile changes, or "
       "privilege escalation."
   ),
   remediation=(
       "1. Implement server-side authorization checks on every request.\n"
       "2. Use indirect references (e.g., session-based mappings) instead of direct IDs.\n"
       "3. Apply the principle of least privilege.\n"
       "4. Log and monitor access patterns for anomalies."
   ),
   references=[
       "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
       "https://cwe.mitre.org/data/definitions/639.html",
   ],
)

_t("broken-access-control",
   title="Broken Access Control on {{endpoint}}",
   vuln_type="broken_access_control",
   severity="high",
   cvss_score=8.2,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
   cwe="CWE-284",
   owasp="A01:2021 — Broken Access Control",
   description=(
       "The {{endpoint}} endpoint does not properly enforce authorization. "
       "A user with lower privileges (or no authentication) can perform actions "
       "or access resources that should be restricted to higher-privilege roles."
   ),
   impact=(
       "Unauthorized users can access administrative functions, modify other users' "
       "data, escalate their privileges, or bypass business logic constraints. "
       "This can lead to full account takeover or application compromise."
   ),
   remediation=(
       "1. Implement role-based access control (RBAC) with deny-by-default.\n"
       "2. Enforce authorization checks server-side on every request.\n"
       "3. Use centralized access control mechanisms.\n"
       "4. Disable directory listing and ensure metadata/backup files aren't accessible.\n"
       "5. Log access control failures and alert on repeated violations."
   ),
   references=[
       "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
       "https://cwe.mitre.org/data/definitions/284.html",
   ],
)

_t("auth-bypass",
   title="Authentication Bypass on {{endpoint}}",
   vuln_type="auth_bypass",
   severity="critical",
   cvss_score=9.8,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
   cwe="CWE-287",
   owasp="A07:2021 — Identification and Authentication Failures",
   description=(
       "The authentication mechanism at {{endpoint}} can be bypassed, allowing "
       "an unauthenticated attacker to gain access to protected resources or "
       "functionality without valid credentials."
   ),
   impact=(
       "Complete bypass of authentication allows an attacker to impersonate any user, "
       "access all protected data, and perform any action within the application. "
       "This can lead to full application compromise."
   ),
   remediation=(
       "1. Implement robust authentication using proven frameworks.\n"
       "2. Enforce authentication checks on every protected endpoint server-side.\n"
       "3. Use multi-factor authentication for sensitive operations.\n"
       "4. Implement account lockout and brute-force protection."
   ),
   references=[
       "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
       "https://cwe.mitre.org/data/definitions/287.html",
   ],
)

# ═══════════════════════════════════════════════════════════════════
# Server-Side Request Forgery
# ═══════════════════════════════════════════════════════════════════

_t("ssrf",
   title="Server-Side Request Forgery (SSRF) on {{endpoint}}",
   vuln_type="ssrf",
   severity="high",
   cvss_score=7.5,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
   cwe="CWE-918",
   owasp="A10:2021 — Server-Side Request Forgery",
   description=(
       "The {{parameter}} parameter at {{endpoint}} accepts a URL or hostname that "
       "the server fetches on behalf of the user. By supplying internal addresses "
       "or cloud metadata URLs, an attacker can make the server issue requests "
       "to internal infrastructure."
   ),
   impact=(
       "An attacker can scan internal networks, access cloud instance metadata "
       "(potentially retrieving IAM credentials), interact with internal services "
       "not exposed to the internet, and in some cases achieve remote code execution "
       "through internal service exploitation."
   ),
   remediation=(
       "1. Validate and sanitize all user-supplied URLs server-side.\n"
       "2. Implement an allowlist of permitted domains/IPs.\n"
       "3. Block requests to private/internal IP ranges and cloud metadata endpoints.\n"
       "4. Use a dedicated HTTP client that does not follow redirects to internal hosts.\n"
       "5. Segment the network to limit impact of SSRF."
   ),
   references=[
       "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
       "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
       "https://cwe.mitre.org/data/definitions/918.html",
   ],
)

_t("ssrf-blind",
   title="Blind Server-Side Request Forgery (SSRF) on {{endpoint}}",
   vuln_type="ssrf",
   severity="medium",
   cvss_score=5.3,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N",
   cwe="CWE-918",
   owasp="A10:2021 — Server-Side Request Forgery",
   description=(
       "The {{parameter}} parameter at {{endpoint}} triggers a server-side HTTP request, "
       "but the response is not returned to the attacker (blind SSRF). The request "
       "was confirmed via out-of-band interaction (e.g., DNS lookup or HTTP callback "
       "to an attacker-controlled server)."
   ),
   impact=(
       "While the attacker cannot directly read responses, blind SSRF can still be used "
       "to scan internal networks, trigger actions on internal services, and in some "
       "cases exfiltrate data through DNS or other side channels."
   ),
   remediation=(
       "1. Validate and sanitize all user-supplied URLs server-side.\n"
       "2. Implement an allowlist of permitted domains/IPs.\n"
       "3. Block requests to private/internal IP ranges.\n"
       "4. Monitor outbound request patterns for anomalies."
   ),
   references=[
       "https://portswigger.net/web-security/ssrf/blind",
       "https://cwe.mitre.org/data/definitions/918.html",
   ],
)

# ═══════════════════════════════════════════════════════════════════
# Information Disclosure
# ═══════════════════════════════════════════════════════════════════

_t("info-disclosure",
   title="Information Disclosure on {{endpoint}}",
   vuln_type="info_disclosure",
   severity="low",
   cvss_score=5.3,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
   cwe="CWE-200",
   owasp="A01:2021 — Broken Access Control",
   description=(
       "The {{endpoint}} endpoint exposes sensitive information that could aid an "
       "attacker in further exploitation. This includes internal paths, stack traces, "
       "version numbers, configuration details, or user data."
   ),
   impact=(
       "Information disclosure provides attackers with intelligence about the "
       "application's technology stack, internal architecture, and potential attack "
       "surface. This information can be used to craft targeted exploits."
   ),
   remediation=(
       "1. Implement proper error handling that returns generic error messages.\n"
       "2. Remove debug endpoints and verbose logging from production.\n"
       "3. Review HTTP response headers for information leakage.\n"
       "4. Restrict access to administrative and diagnostic endpoints."
   ),
   references=[
       "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
       "https://cwe.mitre.org/data/definitions/200.html",
   ],
)

_t("info-source-code",
   title="Source Code Disclosure on {{endpoint}}",
   vuln_type="info_disclosure",
   severity="high",
   cvss_score=7.5,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
   cwe="CWE-540",
   owasp="A05:2021 — Security Misconfiguration",
   description=(
       "The server exposes application source code at {{endpoint}}, either through "
       "misconfigured file serving, backup files, or version control artifacts "
       "(e.g., .git, .svn directories)."
   ),
   impact=(
       "Source code disclosure reveals business logic, authentication mechanisms, "
       "API keys, database credentials, and potential vulnerabilities. An attacker "
       "can use this to identify and exploit additional security flaws."
   ),
   remediation=(
       "1. Block access to source code files, backup files, and VCS directories.\n"
       "2. Configure the web server to serve only intended file types.\n"
       "3. Remove development artifacts from production deployments.\n"
       "4. Use a .gitignore and deployment pipeline that excludes sensitive files."
   ),
   references=[
       "https://cwe.mitre.org/data/definitions/540.html",
       "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
   ],
)

# ═══════════════════════════════════════════════════════════════════
# Misconfiguration
# ═══════════════════════════════════════════════════════════════════

_t("cors",
   title="Misconfigured CORS Policy on {{endpoint}}",
   vuln_type="cors",
   severity="medium",
   cvss_score=5.4,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
   cwe="CWE-942",
   owasp="A05:2021 — Security Misconfiguration",
   description=(
       "The application at {{endpoint}} reflects the Origin header in the "
       "Access-Control-Allow-Origin response header without validation, or uses "
       "overly permissive CORS settings (e.g., wildcard with credentials). "
       "This allows any website to make authenticated cross-origin requests."
   ),
   impact=(
       "An attacker can create a malicious page that makes cross-origin requests "
       "to the vulnerable application using the victim's session. This can lead "
       "to data theft, unauthorized actions, and session hijacking."
   ),
   remediation=(
       "1. Validate the Origin header against a strict allowlist of trusted domains.\n"
       "2. Never reflect arbitrary Origins with Access-Control-Allow-Credentials: true.\n"
       "3. Avoid using wildcard (*) for Access-Control-Allow-Origin when credentials are needed.\n"
       "4. Restrict exposed headers and methods to the minimum required."
   ),
   references=[
       "https://portswigger.net/web-security/cors",
       "https://cwe.mitre.org/data/definitions/942.html",
   ],
)

_t("open-redirect",
   title="Open Redirect on {{endpoint}}",
   vuln_type="open_redirect",
   severity="low",
   cvss_score=4.7,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
   cwe="CWE-601",
   owasp="A01:2021 — Broken Access Control",
   description=(
       "The {{parameter}} parameter at {{endpoint}} is used to redirect users "
       "to an external URL without validation. An attacker can craft a link "
       "that appears legitimate but redirects victims to a malicious site."
   ),
   impact=(
       "Open redirects are primarily used in phishing attacks, making malicious "
       "links appear to originate from a trusted domain. They can also be chained "
       "with other vulnerabilities (e.g., OAuth token theft, SSRF bypass)."
   ),
   remediation=(
       "1. Validate redirect URLs against an allowlist of permitted destinations.\n"
       "2. Use indirect references (e.g., mapping IDs) instead of raw URLs.\n"
       "3. Display a warning page when redirecting to external domains."
   ),
   references=[
       "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
       "https://cwe.mitre.org/data/definitions/601.html",
   ],
)

_t("csrf",
   title="Cross-Site Request Forgery (CSRF) on {{endpoint}}",
   vuln_type="csrf",
   severity="medium",
   cvss_score=6.5,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
   cwe="CWE-352",
   owasp="A01:2021 — Broken Access Control",
   description=(
       "The {{endpoint}} endpoint performs a state-changing action but does not "
       "validate a CSRF token or use other anti-CSRF measures (SameSite cookies, "
       "Origin header verification). An attacker can forge a request that is "
       "automatically submitted by a victim's browser."
   ),
   impact=(
       "An attacker can trick an authenticated user into performing unintended "
       "actions such as changing their email, password, or settings; making "
       "financial transactions; or modifying data — all without the user's knowledge."
   ),
   remediation=(
       "1. Implement anti-CSRF tokens (synchronizer token pattern).\n"
       "2. Set SameSite=Strict or SameSite=Lax on session cookies.\n"
       "3. Verify the Origin/Referer header on state-changing requests.\n"
       "4. Require re-authentication for sensitive operations."
   ),
   references=[
       "https://owasp.org/www-community/attacks/csrf",
       "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
       "https://cwe.mitre.org/data/definitions/352.html",
   ],
)

_t("subdomain-takeover",
   title="Subdomain Takeover — {{target}}",
   vuln_type="subdomain_takeover",
   severity="high",
   cvss_score=8.2,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
   cwe="CWE-284",
   owasp="A05:2021 — Security Misconfiguration",
   description=(
       "The subdomain {{target}} has a DNS record (CNAME/A) pointing to a "
       "third-party service that is no longer provisioned. An attacker can claim "
       "this resource on the hosting provider and serve arbitrary content under "
       "the organization's domain."
   ),
   impact=(
       "An attacker controlling the subdomain can serve phishing pages that appear "
       "legitimate, steal cookies scoped to the parent domain, bypass CSP and CORS "
       "policies, and damage the organization's reputation."
   ),
   remediation=(
       "1. Remove dangling DNS records pointing to deprovisioned services.\n"
       "2. Regularly audit DNS records and external service dependencies.\n"
       "3. Use subdomain monitoring to detect new/changed records.\n"
       "4. Scope cookies to specific subdomains rather than the parent domain."
   ),
   references=[
       "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
       "https://github.com/EdOverflow/can-i-take-over-xyz",
   ],
)

_t("security-headers-missing",
   title="Missing Security Headers on {{endpoint}}",
   vuln_type="info_disclosure",
   severity="informational",
   cvss_score=0.0,
   cvss_vector="N/A",
   cwe="CWE-693",
   owasp="A05:2021 — Security Misconfiguration",
   description=(
       "The application at {{endpoint}} does not set one or more recommended "
       "security headers: Content-Security-Policy, X-Content-Type-Options, "
       "X-Frame-Options, Strict-Transport-Security, Referrer-Policy, "
       "Permissions-Policy."
   ),
   impact=(
       "Missing security headers reduce defense-in-depth protections. Without "
       "CSP, XSS attacks are harder to mitigate. Without HSTS, users are vulnerable "
       "to SSL stripping. Without X-Frame-Options, clickjacking may be possible."
   ),
   remediation=(
       "1. Add Content-Security-Policy header with a restrictive policy.\n"
       "2. Add Strict-Transport-Security: max-age=31536000; includeSubDomains.\n"
       "3. Add X-Content-Type-Options: nosniff.\n"
       "4. Add X-Frame-Options: DENY or SAMEORIGIN.\n"
       "5. Add Referrer-Policy: strict-origin-when-cross-origin.\n"
       "6. Add Permissions-Policy to restrict browser features."
   ),
   references=[
       "https://owasp.org/www-project-secure-headers/",
       "https://securityheaders.com/",
   ],
)

# ═══════════════════════════════════════════════════════════════════
# File/Path
# ═══════════════════════════════════════════════════════════════════

_t("lfi",
   title="Local File Inclusion (LFI) on {{endpoint}}",
   vuln_type="lfi",
   severity="high",
   cvss_score=7.5,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
   cwe="CWE-98",
   owasp="A03:2021 — Injection",
   description=(
       "The {{parameter}} parameter at {{endpoint}} is used to include a file "
       "from the server's filesystem. By using path traversal sequences (../), "
       "an attacker can read arbitrary files such as /etc/passwd, application "
       "configuration, or source code."
   ),
   impact=(
       "An attacker can read sensitive files including configuration files "
       "with credentials, source code, and system files. If log poisoning "
       "or wrapper techniques are available, LFI can escalate to remote "
       "code execution."
   ),
   remediation=(
       "1. Avoid using user input in file paths entirely.\n"
       "2. If necessary, use an allowlist of permitted files/directories.\n"
       "3. Canonicalize and validate paths server-side.\n"
       "4. Use a chroot or container to limit filesystem access."
   ),
   references=[
       "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
       "https://cwe.mitre.org/data/definitions/98.html",
   ],
)

_t("path-traversal",
   title="Path Traversal on {{endpoint}}",
   vuln_type="path_traversal",
   severity="high",
   cvss_score=7.5,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
   cwe="CWE-22",
   owasp="A01:2021 — Broken Access Control",
   description=(
       "The {{parameter}} parameter at {{endpoint}} contains a filename or path "
       "that is used to access files on the server. The application does not "
       "properly sanitize path traversal sequences (../, ..\\), allowing an "
       "attacker to access files outside the intended directory."
   ),
   impact=(
       "An attacker can read (and potentially write) arbitrary files on the "
       "server, including configuration files, credentials, source code, "
       "and sensitive system files."
   ),
   remediation=(
       "1. Validate file paths against an allowlist.\n"
       "2. Canonicalize the path and verify it stays within the expected directory.\n"
       "3. Use a chroot or sandboxed filesystem.\n"
       "4. Avoid passing user input directly to filesystem operations."
   ),
   references=[
       "https://owasp.org/www-community/attacks/Path_Traversal",
       "https://cwe.mitre.org/data/definitions/22.html",
   ],
)

# ═══════════════════════════════════════════════════════════════════
# Deserialization / XXE / RCE
# ═══════════════════════════════════════════════════════════════════

_t("xxe",
   title="XML External Entity (XXE) Injection on {{endpoint}}",
   vuln_type="xxe",
   severity="high",
   cvss_score=7.5,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
   cwe="CWE-611",
   owasp="A05:2021 — Security Misconfiguration",
   description=(
       "The {{endpoint}} endpoint processes XML input with external entity "
       "processing enabled. An attacker can define external entities that cause "
       "the server to read local files, make network requests, or trigger "
       "denial of service."
   ),
   impact=(
       "An attacker can read arbitrary files from the server, perform SSRF attacks "
       "against internal services, enumerate internal network topology, and in "
       "some cases achieve remote code execution."
   ),
   remediation=(
       "1. Disable external entity processing in the XML parser.\n"
       "2. Disable DTD processing entirely if not required.\n"
       "3. Use less complex data formats (JSON) where possible.\n"
       "4. Validate and sanitize XML input."
   ),
   references=[
       "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
       "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
       "https://cwe.mitre.org/data/definitions/611.html",
   ],
)

_t("rce",
   title="Remote Code Execution on {{endpoint}}",
   vuln_type="rce",
   severity="critical",
   cvss_score=9.8,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
   cwe="CWE-94",
   owasp="A03:2021 — Injection",
   description=(
       "The {{endpoint}} endpoint allows an attacker to execute arbitrary code "
       "on the server. The vulnerability exists because user-supplied input is "
       "passed to a code evaluation function (e.g., eval, exec, unserialize) "
       "without proper validation."
   ),
   impact=(
       "An attacker achieves full control over the server, with the ability to "
       "execute arbitrary commands, read/write any files, install backdoors, "
       "pivot to internal systems, and exfiltrate all data."
   ),
   remediation=(
       "1. Never use eval(), exec(), or similar functions with user input.\n"
       "2. Use type-safe deserialization with allowlists.\n"
       "3. Implement application sandboxing and least privilege.\n"
       "4. Apply input validation and WAF rules as defense-in-depth."
   ),
   references=[
       "https://owasp.org/www-community/attacks/Code_Injection",
       "https://cwe.mitre.org/data/definitions/94.html",
   ],
)

_t("deserialization",
   title="Insecure Deserialization on {{endpoint}}",
   vuln_type="deserialization",
   severity="critical",
   cvss_score=9.8,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
   cwe="CWE-502",
   owasp="A08:2021 — Software and Data Integrity Failures",
   description=(
       "The application at {{endpoint}} deserializes user-controllable data "
       "without validation. An attacker can supply a crafted serialized object "
       "that triggers arbitrary code execution during deserialization."
   ),
   impact=(
       "Insecure deserialization can lead to remote code execution, privilege "
       "escalation, denial of service, and authentication bypass, depending "
       "on available gadget chains."
   ),
   remediation=(
       "1. Do not deserialize untrusted data.\n"
       "2. Use data formats that do not support object instantiation (JSON).\n"
       "3. If deserialization is required, use type-safe schemas and allowlists.\n"
       "4. Implement integrity checks (HMAC) on serialized data.\n"
       "5. Monitor deserialization and alert on failures."
   ),
   references=[
       "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
       "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
       "https://cwe.mitre.org/data/definitions/502.html",
   ],
)

# ═══════════════════════════════════════════════════════════════════
# Business Logic / Race Conditions
# ═══════════════════════════════════════════════════════════════════

_t("race-condition",
   title="Race Condition on {{endpoint}}",
   vuln_type="race_condition",
   severity="medium",
   cvss_score=5.9,
   cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
   cwe="CWE-362",
   owasp="A04:2021 — Insecure Design",
   description=(
       "The {{endpoint}} endpoint is vulnerable to a race condition (TOCTOU). "
       "By sending multiple concurrent requests, an attacker can exploit the "
       "timing window between a check and its corresponding action to bypass "
       "business logic constraints."
   ),
   impact=(
       "Depending on the affected functionality, this can lead to double-spending, "
       "bypassing rate limits, applying discounts multiple times, creating duplicate "
       "resources, or exceeding allowed quotas."
   ),
   remediation=(
       "1. Use database-level locks or atomic operations for critical sections.\n"
       "2. Implement idempotency keys for state-changing operations.\n"
       "3. Use serializable transaction isolation where needed.\n"
       "4. Apply mutex/locks at the application level."
   ),
   references=[
       "https://portswigger.net/web-security/race-conditions",
       "https://cwe.mitre.org/data/definitions/362.html",
   ],
)

_t("business-logic",
   title="Business Logic Flaw on {{endpoint}}",
   vuln_type="business_logic",
   severity="medium",
   cvss_score=6.5,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
   cwe="CWE-840",
   owasp="A04:2021 — Insecure Design",
   description=(
       "The application's business logic at {{endpoint}} contains a flaw that "
       "allows an attacker to abuse the intended workflow to achieve an unintended "
       "outcome. The application fails to enforce expected constraints or "
       "validates assumptions client-side only."
   ),
   impact=(
       "The impact depends on the specific business function affected. Common "
       "impacts include financial loss, data manipulation, privilege escalation, "
       "or bypassing intended restrictions."
   ),
   remediation=(
       "1. Enforce all business rules server-side.\n"
       "2. Implement comprehensive validation at each step of multi-step workflows.\n"
       "3. Define and test abuse cases alongside functional test cases.\n"
       "4. Apply the principle of least privilege to all operations."
   ),
   references=[
       "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
       "https://cwe.mitre.org/data/definitions/840.html",
   ],
)

# ═══════════════════════════════════════════════════════════════════
# Other
# ═══════════════════════════════════════════════════════════════════

_t("crlf",
   title="CRLF Injection / HTTP Response Splitting on {{endpoint}}",
   vuln_type="crlf",
   severity="medium",
   cvss_score=6.1,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
   cwe="CWE-113",
   owasp="A03:2021 — Injection",
   description=(
       "The {{parameter}} parameter at {{endpoint}} is reflected in HTTP response "
       "headers without stripping carriage return (\\r) and line feed (\\n) "
       "characters. This allows an attacker to inject arbitrary headers or "
       "split the HTTP response."
   ),
   impact=(
       "An attacker can set arbitrary cookies, inject security-relevant headers, "
       "perform HTTP response splitting to poison caches or deliver XSS payloads "
       "in forged response bodies."
   ),
   remediation=(
       "1. Strip or encode CRLF characters (\\r\\n) from user input before "
       "including it in HTTP headers.\n"
       "2. Use framework-provided methods for setting headers.\n"
       "3. Validate header values against an allowlist where possible."
   ),
   references=[
       "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
       "https://cwe.mitre.org/data/definitions/113.html",
   ],
)

_t("hhi",
   title="Host Header Injection on {{endpoint}}",
   vuln_type="hhi",
   severity="medium",
   cvss_score=6.1,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
   cwe="CWE-644",
   owasp="A05:2021 — Security Misconfiguration",
   description=(
       "The application at {{endpoint}} trusts the Host header (or X-Forwarded-Host) "
       "to generate URLs (e.g., password reset links, redirects). An attacker can "
       "manipulate this header to point generated URLs to an attacker-controlled domain."
   ),
   impact=(
       "Primarily exploited in password reset poisoning: the victim receives a "
       "legitimate password reset email containing a link to the attacker's domain, "
       "leaking the reset token. Can also enable cache poisoning and routing-based SSRF."
   ),
   remediation=(
       "1. Do not use the Host header to generate URLs; configure the canonical hostname.\n"
       "2. Validate the Host header against an allowlist.\n"
       "3. Use absolute URLs from configuration rather than request-derived values."
   ),
   references=[
       "https://portswigger.net/web-security/host-header",
       "https://cwe.mitre.org/data/definitions/644.html",
   ],
)

_t("prototype-pollution",
   title="Prototype Pollution on {{endpoint}}",
   vuln_type="prototype_pollution",
   severity="medium",
   cvss_score=6.3,
   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
   cwe="CWE-1321",
   owasp="A03:2021 — Injection",
   description=(
       "The application at {{endpoint}} merges user-supplied JSON into JavaScript "
       "objects without filtering __proto__ or constructor.prototype properties. "
       "An attacker can inject properties into Object.prototype that affect "
       "the behavior of all objects in the application."
   ),
   impact=(
       "Prototype pollution can lead to denial of service, property injection for "
       "authorization bypass, and in some cases remote code execution through "
       "gadget chains (e.g., polluting options passed to child_process or template engines)."
   ),
   remediation=(
       "1. Use Object.create(null) for dictionary-like objects.\n"
       "2. Filter keys (__proto__, constructor, prototype) from user input.\n"
       "3. Freeze Object.prototype in security-sensitive contexts.\n"
       "4. Use Map instead of plain objects for user-controlled keys."
   ),
   references=[
       "https://portswigger.net/web-security/prototype-pollution",
       "https://cwe.mitre.org/data/definitions/1321.html",
   ],
)


# ═══════════════════════════════════════════════════════════════════
# Query helpers
# ═══════════════════════════════════════════════════════════════════

def list_template_keys() -> list[str]:
    """Return all available template keys sorted."""
    return sorted(VULN_TEMPLATES.keys())


def get_template(key: str) -> dict | None:
    """Get a template by its key."""
    return VULN_TEMPLATES.get(key)


def search_templates(query: str) -> list[dict]:
    """Search templates by keyword in key, title, description, vuln_type, or CWE."""
    query = query.lower()
    results = []
    for t in VULN_TEMPLATES.values():
        searchable = " ".join([
            t.get("key", ""), t.get("title", ""), t.get("description", ""),
            t.get("vuln_type", ""), t.get("cwe", ""), t.get("owasp", ""),
        ]).lower()
        if query in searchable:
            results.append(t)
    return results


def get_templates_by_category() -> dict[str, list[dict]]:
    """Group templates by OWASP category."""
    groups: dict[str, list[dict]] = {}
    for t in VULN_TEMPLATES.values():
        cat = t.get("owasp", "Other")
        groups.setdefault(cat, []).append(t)
    return groups


def fill_template(key: str, target: str = "", endpoint: str = "",
                  parameter: str = "") -> dict | None:
    """
    Get a template with placeholders filled in.

    Returns a dict ready for vuln creation (title, description, impact,
    remediation, severity, cvss_score, cvss_vector, vuln_type, cwe, owasp,
    references).
    """
    tpl = get_template(key)
    if not tpl:
        return None
    filled = {}
    for field in ("title", "description", "impact", "remediation"):
        val = tpl.get(field, "")
        val = val.replace("{{target}}", target or "TARGET")
        val = val.replace("{{endpoint}}", endpoint or "ENDPOINT")
        val = val.replace("{{parameter}}", parameter or "PARAMETER")
        val = val.replace("{{domain}}", target or "DOMAIN")
        filled[field] = val
    for field in ("vuln_type", "severity", "cvss_score", "cvss_vector", "cwe", "owasp", "references"):
        filled[field] = tpl.get(field)
    return filled
