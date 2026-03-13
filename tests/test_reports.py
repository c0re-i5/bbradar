"""
Tests for report generation — particularly HTML XSS safety.
"""

import pytest
from bbradar.modules.projects import create_project
from bbradar.modules.vulns import create_vuln
from bbradar.modules.reports import (
    generate_single_vuln_report,
    generate_full_report,
    generate_executive_summary,
)


@pytest.fixture
def project_with_vuln(tmp_db, tmp_path):
    pid = create_project("ReportTest", db_path=tmp_db)
    vid = create_vuln(
        pid, "XSS in <script>alert(1)</script>",
        severity="high", vuln_type="xss",
        description="Found XSS with payload <img src=x onerror=alert(1)>",
        db_path=tmp_db,
    )
    return pid, vid, tmp_db, tmp_path


class TestHTMLSafety:
    def test_title_escaped_in_html(self, project_with_vuln):
        pid, vid, db, tmp_path = project_with_vuln
        output = str(tmp_path / "test.html")
        path = generate_single_vuln_report(vid, format="html", output_path=output, db_path=db)
        content = open(path).read()
        # The <title> tag should have escaped HTML
        assert "<script>alert(1)</script>" not in content.split("<title>")[1].split("</title>")[0]

    def test_markdown_report_generates(self, project_with_vuln):
        pid, vid, db, tmp_path = project_with_vuln
        output = str(tmp_path / "test.md")
        path = generate_single_vuln_report(vid, format="markdown", output_path=output, db_path=db)
        content = open(path).read()
        assert "XSS" in content

    def test_full_report(self, project_with_vuln):
        pid, vid, db, tmp_path = project_with_vuln
        output = str(tmp_path / "full.md")
        path = generate_full_report(pid, format="markdown", output_path=output, db_path=db)
        content = open(path).read()
        assert "ReportTest" in content

    def test_executive_summary(self, project_with_vuln):
        pid, vid, db, tmp_path = project_with_vuln
        output = str(tmp_path / "exec.md")
        path = generate_executive_summary(pid, format="markdown", output_path=output, db_path=db)
        content = open(path).read()
        assert "Executive" in content or "Summary" in content


class TestReportErrors:
    def test_nonexistent_vuln(self, tmp_db, tmp_path):
        with pytest.raises(ValueError, match="not found"):
            generate_single_vuln_report(999, output_path=str(tmp_path / "x.md"), db_path=tmp_db)

    def test_nonexistent_project(self, tmp_db, tmp_path):
        with pytest.raises((ValueError, Exception)):
            generate_full_report(999, output_path=str(tmp_path / "x.md"), db_path=tmp_db)
