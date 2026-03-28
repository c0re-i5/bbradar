"""
Tests for CVE (NVD), CISA KEV, and EPSS integration.

Tests sync parsing, lookup, enrichment, search, and notifications
using mocked HTTP responses.
"""

import json
from unittest.mock import patch, MagicMock

import pytest

from bbradar.core.database import get_connection, init_db
from bbradar.modules import knowledgebase, notifier


# ═══════════════════════════════════════════════════════════════════
# Mock data builders
# ═══════════════════════════════════════════════════════════════════

def _nvd_cve_entry(cve_id="CVE-2024-1234", description="Test vuln description",
                   score=9.8, severity="CRITICAL", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                   cwes=None, products=None, published="2024-01-15T10:00:00.000",
                   modified="2024-01-16T08:00:00.000"):
    """Build a mock NVD CVE entry matching API 2.0 response format."""
    entry = {
        "cve": {
            "id": cve_id,
            "descriptions": [
                {"lang": "en", "value": description},
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": score,
                            "vectorString": vector,
                            "baseSeverity": severity,
                        }
                    }
                ] if score else [],
            },
            "weaknesses": [
                {
                    "description": [
                        {"lang": "en", "value": cwe}
                    ]
                }
                for cwe in (cwes or ["CWE-79"])
            ],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": cpe}
                                for cpe in (products or ["cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"])
                            ]
                        }
                    ]
                }
            ],
            "references": [
                {"url": "https://example.com/advisory", "source": "vendor", "tags": ["Vendor Advisory"]},
            ],
            "published": published,
            "lastModified": modified,
        }
    }
    return entry


def _nvd_response(cves=None, total_results=None):
    """Build a mock NVD API response."""
    cves = cves or [_nvd_cve_entry()]
    return json.dumps({
        "resultsPerPage": len(cves),
        "startIndex": 0,
        "totalResults": total_results if total_results is not None else len(cves),
        "vulnerabilities": cves,
    }).encode("utf-8")


def _kev_catalog(entries=None):
    """Build a mock CISA KEV catalog JSON."""
    entries = entries or [
        {
            "cveID": "CVE-2024-1234",
            "vendorProject": "Apache",
            "product": "HTTP Server",
            "vulnerabilityName": "Apache HTTP Server RCE",
            "shortDescription": "A remote code execution vulnerability.",
            "dateAdded": "2024-01-20",
            "dueDate": "2024-02-10",
            "requiredAction": "Apply updates per vendor instructions.",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
        },
    ]
    return json.dumps({
        "title": "CISA KEV Catalog",
        "catalogVersion": "2024.01.20",
        "vulnerabilities": entries,
    }).encode("utf-8")


def _epss_response(entries=None):
    """Build a mock EPSS API response."""
    entries = entries or [
        {"cve": "CVE-2024-1234", "epss": "0.95432", "percentile": "0.99123"},
    ]
    return json.dumps({
        "status": "OK",
        "status-code": 200,
        "model_version": "v2024.01.01",
        "score_date": "2024-01-20",
        "data": entries,
    }).encode("utf-8")


# ═══════════════════════════════════════════════════════════════════
# Tests: NVD CVE Parsing
# ═══════════════════════════════════════════════════════════════════

class TestCVEParsing:
    def test_parse_nvd_cve_basic(self):
        entry = _nvd_cve_entry()
        row = knowledgebase._parse_nvd_cve(entry["cve"])
        assert row is not None
        cve_id, desc, score, vector, severity, cwe_json, products_json, refs_json, pub, mod = row
        assert cve_id == "CVE-2024-1234"
        assert desc == "Test vuln description"
        assert score == 9.8
        assert severity == "CRITICAL"
        assert "CWE-79" in json.loads(cwe_json)
        assert pub == "2024-01-15T10:00:00.000"

    def test_parse_nvd_cve_no_cvss(self):
        entry = _nvd_cve_entry(score=None, vector=None, severity=None)
        entry["cve"]["metrics"]["cvssMetricV31"] = []
        row = knowledgebase._parse_nvd_cve(entry["cve"])
        assert row is not None
        assert row[2] is None  # score
        assert row[3] is None  # vector
        assert row[4] is None  # severity

    def test_parse_nvd_cve_multiple_cwes(self):
        entry = _nvd_cve_entry(cwes=["CWE-79", "CWE-89"])
        row = knowledgebase._parse_nvd_cve(entry["cve"])
        cwe_ids = json.loads(row[5])
        assert "CWE-79" in cwe_ids
        assert "CWE-89" in cwe_ids

    def test_parse_nvd_cve_noinfo_cwe_excluded(self):
        entry = _nvd_cve_entry(cwes=["CWE-noinfo"])
        row = knowledgebase._parse_nvd_cve(entry["cve"])
        assert row[5] is None  # cwe_ids should be None (empty after filter)

    def test_parse_nvd_cve_empty_id_returns_none(self):
        row = knowledgebase._parse_nvd_cve({"id": "", "descriptions": []})
        assert row is None

    def test_parse_nvd_cve_no_id_returns_none(self):
        row = knowledgebase._parse_nvd_cve({})
        assert row is None


class TestCVESync:
    @patch("bbradar.modules.knowledgebase._should_skip", return_value=False)
    @patch("bbradar.modules.knowledgebase._get_sync_info", return_value=None)
    @patch("bbradar.modules.knowledgebase._fetch")
    @patch("bbradar.modules.knowledgebase._set_sync_info")
    def test_sync_cve_initial(self, mock_set, mock_fetch, mock_info, mock_skip, tmp_db):
        mock_fetch.return_value = (_nvd_response(), None, None)
        result = knowledgebase.sync_cve(force=True, db_path=tmp_db)
        assert result["status"] == "updated"
        assert result["records"] >= 1

        # Verify data in DB
        with get_connection(tmp_db) as conn:
            row = conn.execute("SELECT * FROM kb_cve WHERE cve_id = 'CVE-2024-1234'").fetchone()
            assert row is not None
            assert row["cvss_v31_score"] == 9.8

    @patch("bbradar.modules.knowledgebase._should_skip", return_value=True)
    @patch("bbradar.modules.knowledgebase._get_sync_info", return_value={"record_count": 100})
    def test_sync_cve_skipped(self, mock_info, mock_skip, tmp_db):
        result = knowledgebase.sync_cve(db_path=tmp_db)
        assert result["status"] == "skipped"
        assert result["records"] == 100

    @patch("bbradar.modules.knowledgebase._should_skip", return_value=False)
    @patch("bbradar.modules.knowledgebase._get_sync_info", return_value=None)
    @patch("bbradar.modules.knowledgebase._fetch")
    def test_sync_cve_http_error(self, mock_fetch, mock_info, mock_skip, tmp_db):
        from urllib.error import URLError
        mock_fetch.side_effect = URLError("timeout")
        result = knowledgebase.sync_cve(force=True, db_path=tmp_db)
        assert result["status"] == "error"

    @patch("bbradar.modules.knowledgebase._should_skip", return_value=False)
    @patch("bbradar.modules.knowledgebase._get_sync_info", return_value=None)
    @patch("bbradar.modules.knowledgebase._fetch")
    @patch("bbradar.modules.knowledgebase._set_sync_info")
    def test_sync_cve_multiple_entries(self, mock_set, mock_fetch, mock_info, mock_skip, tmp_db):
        entries = [
            _nvd_cve_entry(cve_id="CVE-2024-0001", score=7.5, severity="HIGH"),
            _nvd_cve_entry(cve_id="CVE-2024-0002", score=5.0, severity="MEDIUM"),
            _nvd_cve_entry(cve_id="CVE-2024-0003", score=3.1, severity="LOW"),
        ]
        mock_fetch.return_value = (_nvd_response(entries), None, None)
        result = knowledgebase.sync_cve(force=True, db_path=tmp_db)
        assert result["status"] == "updated"

        with get_connection(tmp_db) as conn:
            count = conn.execute("SELECT COUNT(*) as c FROM kb_cve").fetchone()["c"]
            assert count == 3


# ═══════════════════════════════════════════════════════════════════
# Tests: CISA KEV Sync
# ═══════════════════════════════════════════════════════════════════

class TestKEVSync:
    @patch("bbradar.modules.knowledgebase._should_skip", return_value=False)
    @patch("bbradar.modules.knowledgebase._get_sync_info", return_value=None)
    @patch("bbradar.modules.knowledgebase._fetch")
    @patch("bbradar.modules.knowledgebase._set_sync_info")
    def test_sync_kev_initial(self, mock_set, mock_fetch, mock_info, mock_skip, tmp_db):
        mock_fetch.return_value = (_kev_catalog(), "etag123", "Mon, 20 Jan 2024")
        result = knowledgebase.sync_kev(force=True, db_path=tmp_db)
        assert result["status"] == "updated"
        assert result["records"] == 1
        assert len(result.get("new_kev_entries", [])) == 1

        # Verify data in DB
        with get_connection(tmp_db) as conn:
            row = conn.execute("SELECT * FROM kb_kev WHERE cve_id = 'CVE-2024-1234'").fetchone()
            assert row is not None
            assert row["vendor"] == "Apache"
            assert row["known_ransomware"] == "Known"

    @patch("bbradar.modules.knowledgebase._should_skip", return_value=False)
    @patch("bbradar.modules.knowledgebase._get_sync_info", return_value={"etag": "old", "last_modified": None, "file_hash": None})
    @patch("bbradar.modules.knowledgebase._fetch")
    def test_sync_kev_not_modified_304(self, mock_fetch, mock_info, mock_skip, tmp_db):
        mock_fetch.return_value = (None, "old", None)
        result = knowledgebase.sync_kev(db_path=tmp_db)
        assert result["status"] == "not_modified"

    @patch("bbradar.modules.knowledgebase._should_skip", return_value=False)
    @patch("bbradar.modules.knowledgebase._get_sync_info", return_value=None)
    @patch("bbradar.modules.knowledgebase._fetch")
    @patch("bbradar.modules.knowledgebase._set_sync_info")
    def test_sync_kev_tracks_new_entries(self, mock_set, mock_fetch, mock_info, mock_skip, tmp_db):
        # First sync
        entries = [
            {"cveID": "CVE-2024-0001", "vendorProject": "V1", "product": "P1",
             "vulnerabilityName": "Vuln1", "shortDescription": "desc1",
             "dateAdded": "2024-01-10", "dueDate": "2024-02-01",
             "requiredAction": "Patch", "knownRansomwareCampaignUse": "Unknown", "notes": ""},
        ]
        mock_fetch.return_value = (_kev_catalog(entries), "e1", "lm1")
        result1 = knowledgebase.sync_kev(force=True, db_path=tmp_db)
        assert len(result1.get("new_kev_entries", [])) == 1

        # Second sync with additional entry
        entries.append({
            "cveID": "CVE-2024-0002", "vendorProject": "V2", "product": "P2",
            "vulnerabilityName": "Vuln2", "shortDescription": "desc2",
            "dateAdded": "2024-01-20", "dueDate": "2024-02-10",
            "requiredAction": "Patch", "knownRansomwareCampaignUse": "Known", "notes": "",
        })
        mock_info.return_value = {"etag": "e1", "last_modified": "lm1", "file_hash": "old_hash"}
        mock_fetch.return_value = (_kev_catalog(entries), "e2", "lm2")
        result2 = knowledgebase.sync_kev(force=True, db_path=tmp_db)
        assert result2["records"] == 2
        # Only the second entry is new
        assert len(result2.get("new_kev_entries", [])) == 1
        assert result2["new_kev_entries"][0]["cve_id"] == "CVE-2024-0002"


# ═══════════════════════════════════════════════════════════════════
# Tests: EPSS Sync
# ═══════════════════════════════════════════════════════════════════

class TestEPSSSync:
    def test_sync_epss_with_explicit_cves(self, tmp_db):
        with patch("bbradar.modules.knowledgebase._fetch") as mock_fetch, \
             patch("bbradar.modules.knowledgebase._set_sync_info"):
            mock_fetch.return_value = (_epss_response(), None, None)
            result = knowledgebase.sync_epss(
                force=True, db_path=tmp_db,
                cve_ids=["CVE-2024-1234"],
            )
            assert result["status"] == "updated"
            assert result["records"] >= 1

            # Verify data
            with get_connection(tmp_db) as conn:
                row = conn.execute("SELECT * FROM kb_epss WHERE cve_id = 'CVE-2024-1234'").fetchone()
                assert row is not None
                assert row["epss_score"] == pytest.approx(0.95432, abs=0.001)
                assert row["percentile"] == pytest.approx(0.99123, abs=0.001)
                assert row["model_version"] == "v2024.01.01"

    def test_sync_epss_no_cves_needed(self, tmp_db):
        with patch("bbradar.modules.knowledgebase._should_skip", return_value=False), \
             patch("bbradar.modules.knowledgebase._set_sync_info"):
            # No CVEs in kb_cve → nothing to fetch
            result = knowledgebase.sync_epss(force=True, db_path=tmp_db)
            assert result["status"] == "not_modified"

    def test_sync_epss_batches_large_lists(self, tmp_db):
        """EPSS API limits to 100 CVEs per request."""
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(150)]
        entries = [{"cve": c, "epss": "0.5", "percentile": "0.5"} for c in cve_ids[:100]]
        entries2 = [{"cve": c, "epss": "0.3", "percentile": "0.3"} for c in cve_ids[100:]]

        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return (_epss_response(entries), None, None)
            else:
                return (_epss_response(entries2), None, None)

        with patch("bbradar.modules.knowledgebase._fetch", side_effect=side_effect), \
             patch("bbradar.modules.knowledgebase._set_sync_info"), \
             patch("time.sleep"):
            result = knowledgebase.sync_epss(
                force=True, db_path=tmp_db, cve_ids=cve_ids,
            )
            assert result["status"] == "updated"
            assert call_count[0] == 2  # Two batches


# ═══════════════════════════════════════════════════════════════════
# Tests: CVE Lookup
# ═══════════════════════════════════════════════════════════════════

class TestCVELookup:
    def _seed_cve(self, db_path):
        """Insert test CVE, KEV, and EPSS data."""
        with get_connection(db_path) as conn:
            conn.execute("""
                INSERT INTO kb_cve (cve_id, description, cvss_v31_score, cvss_v31_vector,
                    cvss_v31_severity, cwe_ids, affected_products, "references",
                    published_at, modified_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("CVE-2024-1234", "Remote code execution in Example",
                  9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL",
                  json.dumps(["CWE-94"]),
                  json.dumps(["cpe:2.3:a:example:server:1.0:*:*:*:*:*:*:*"]),
                  json.dumps([{"url": "https://example.com/advisory", "source": "vendor", "tags": []}]),
                  "2024-01-15T10:00:00", "2024-01-16T08:00:00"))

            conn.execute("""
                INSERT INTO kb_kev (cve_id, vendor, product, name, description,
                    date_added, due_date, required_action, known_ransomware, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("CVE-2024-1234", "Example", "Server", "Example Server RCE",
                  "Remote code execution", "2024-01-20", "2024-02-10",
                  "Apply patch", "Known", ""))

            conn.execute("""
                INSERT INTO kb_epss (cve_id, epss_score, percentile, model_version, score_date)
                VALUES (?, ?, ?, ?, ?)
            """, ("CVE-2024-1234", 0.95, 0.99, "v2024.01.01", "2024-01-20"))

    def test_lookup_cve_full(self, tmp_db):
        self._seed_cve(tmp_db)
        result = knowledgebase.lookup_cve("CVE-2024-1234", db_path=tmp_db)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-1234"
        assert result["cvss_v31_score"] == 9.8
        assert result["actively_exploited"] is True
        assert "kev" in result
        assert result["kev"]["vendor"] == "Example"
        assert "epss" in result
        assert result["epss"]["epss_score"] == pytest.approx(0.95)

    def test_lookup_cve_normalize_id(self, tmp_db):
        self._seed_cve(tmp_db)
        # Without CVE- prefix
        result = knowledgebase.lookup_cve("2024-1234", db_path=tmp_db)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-1234"

    def test_lookup_cve_not_exploited(self, tmp_db):
        """CVE in DB but not in KEV catalog."""
        with get_connection(tmp_db) as conn:
            conn.execute("""
                INSERT INTO kb_cve (cve_id, description, published_at, modified_at)
                VALUES (?, ?, ?, ?)
            """, ("CVE-2024-9999", "Benign vuln", "2024-06-01", "2024-06-02"))
        result = knowledgebase.lookup_cve("CVE-2024-9999", db_path=tmp_db)
        assert result is not None
        assert result["actively_exploited"] is False
        assert "kev" not in result

    def test_lookup_cve_kev_only(self, tmp_db):
        """CVE in KEV but not yet in NVD data."""
        with get_connection(tmp_db) as conn:
            conn.execute("""
                INSERT INTO kb_kev (cve_id, vendor, product, name, description,
                    date_added, due_date, required_action, known_ransomware, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("CVE-2024-5555", "Vendor", "Product", "Zero Day",
                  "Actively exploited zero day", "2024-01-25", "2024-02-15",
                  "Apply mitigations", "Unknown", ""))
        result = knowledgebase.lookup_cve("CVE-2024-5555", db_path=tmp_db)
        assert result is not None
        assert result["actively_exploited"] is True
        assert result["description"] == "Actively exploited zero day"

    def test_lookup_cve_not_found(self, tmp_db):
        result = knowledgebase.lookup_cve("CVE-9999-9999", db_path=tmp_db)
        assert result is None

    def test_lookup_cve_json_fields_deserialized(self, tmp_db):
        self._seed_cve(tmp_db)
        result = knowledgebase.lookup_cve("CVE-2024-1234", db_path=tmp_db)
        assert isinstance(result["cwe_ids"], list)
        assert isinstance(result["affected_products"], list)
        assert isinstance(result["references"], list)


# ═══════════════════════════════════════════════════════════════════
# Tests: Search
# ═══════════════════════════════════════════════════════════════════

class TestSearchCVE:
    def test_search_includes_cve_results(self, tmp_db):
        with get_connection(tmp_db) as conn:
            conn.execute("""
                INSERT INTO kb_cve (cve_id, description, cvss_v31_score, cvss_v31_severity,
                    published_at, modified_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ("CVE-2024-1234", "SQL injection in login form", 9.8, "CRITICAL",
                  "2024-01-15", "2024-01-16"))
        results = knowledgebase.search_kb("SQL injection", db_path=tmp_db)
        assert "cve" in results
        assert len(results["cve"]) == 1
        assert results["cve"][0]["cve_id"] == "CVE-2024-1234"

    def test_search_includes_kev_results(self, tmp_db):
        with get_connection(tmp_db) as conn:
            conn.execute("""
                INSERT INTO kb_kev (cve_id, vendor, product, name, description,
                    date_added, due_date, required_action, known_ransomware, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("CVE-2024-5678", "Apache", "Struts", "Apache Struts RCE",
                  "Remote code execution", "2024-01-20", "2024-02-10",
                  "Patch", "Unknown", ""))
        results = knowledgebase.search_kb("Apache Struts", db_path=tmp_db)
        assert "kev" in results
        assert len(results["kev"]) >= 1

    def test_search_cve_by_id(self, tmp_db):
        with get_connection(tmp_db) as conn:
            conn.execute("""
                INSERT INTO kb_cve (cve_id, description, published_at, modified_at)
                VALUES (?, ?, ?, ?)
            """, ("CVE-2024-4321", "Buffer overflow", "2024-03-01", "2024-03-02"))
        results = knowledgebase.search_kb("CVE-2024-4321", db_path=tmp_db)
        assert len(results["cve"]) == 1


# ═══════════════════════════════════════════════════════════════════
# Tests: CVE Enrichment
# ═══════════════════════════════════════════════════════════════════

class TestCVEEnrichment:
    def _seed_all(self, db_path):
        """Seed CVE, KEV, and EPSS data."""
        with get_connection(db_path) as conn:
            conn.execute("""
                INSERT INTO kb_cve (cve_id, description, cvss_v31_score,
                    cvss_v31_severity, published_at, modified_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ("CVE-2024-1234", "RCE in Example", 9.8, "CRITICAL",
                  "2024-01-15", "2024-01-16"))
            conn.execute("""
                INSERT INTO kb_kev (cve_id, vendor, product, name, description,
                    date_added, due_date, required_action, known_ransomware, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("CVE-2024-1234", "Example", "Server", "RCE",
                  "Remote code execution", "2024-01-20", "2024-02-10",
                  "Patch", "Known", ""))
            conn.execute("""
                INSERT INTO kb_epss (cve_id, epss_score, percentile, model_version, score_date)
                VALUES (?, ?, ?, ?, ?)
            """, ("CVE-2024-1234", 0.95, 0.99, "v1", "2024-01-20"))

    def test_enrich_vuln_with_cve(self, tmp_db):
        self._seed_all(tmp_db)
        vuln = {"description": "Found CVE-2024-1234 in target", "vuln_type": "rce"}
        enrichment = knowledgebase.enrich_vuln(vuln, db_path=tmp_db)
        assert "cve_details" in enrichment
        assert enrichment["cve_details"][0]["cve_id"] == "CVE-2024-1234"
        assert enrichment["actively_exploited"] is True
        assert enrichment["max_epss_score"] == pytest.approx(0.95)

    def test_enrich_vuln_with_explicit_cve_field(self, tmp_db):
        self._seed_all(tmp_db)
        vuln = {"description": "Some vuln", "cve_id": "CVE-2024-1234"}
        enrichment = knowledgebase.enrich_vuln(vuln, db_path=tmp_db)
        assert "cve_details" in enrichment

    def test_enrich_vuln_no_cve(self, tmp_db):
        vuln = {"description": "No CVE references here", "vuln_type": ""}
        enrichment = knowledgebase.enrich_vuln(vuln, db_path=tmp_db)
        assert "cve_details" not in enrichment


# ═══════════════════════════════════════════════════════════════════
# Tests: KB Stats
# ═══════════════════════════════════════════════════════════════════

class TestKBStats:
    def test_stats_includes_new_tables(self, tmp_db):
        stats = knowledgebase.kb_stats(db_path=tmp_db)
        assert "cve" in stats
        assert "kev" in stats
        assert "epss" in stats
        # All should be 0 in empty DB
        assert stats["cve"] == 0
        assert stats["kev"] == 0
        assert stats["epss"] == 0

    def test_stats_counts_inserted_records(self, tmp_db):
        with get_connection(tmp_db) as conn:
            conn.execute("""
                INSERT INTO kb_cve (cve_id, description, published_at, modified_at)
                VALUES ('CVE-2024-0001', 'Test', '2024-01-01', '2024-01-02')
            """)
            conn.execute("""
                INSERT INTO kb_kev (cve_id, vendor, product, name, description,
                    date_added, due_date, required_action, known_ransomware, notes)
                VALUES ('CVE-2024-0001', 'V', 'P', 'N', 'D', '2024-01-01',
                        '2024-02-01', 'Patch', 'Unknown', '')
            """)
        stats = knowledgebase.kb_stats(db_path=tmp_db)
        assert stats["cve"] == 1
        assert stats["kev"] == 1


# ═══════════════════════════════════════════════════════════════════
# Tests: KEV Notifications
# ═══════════════════════════════════════════════════════════════════

class TestKEVNotifications:
    def test_build_kev_embed(self):
        entries = [
            {"cve_id": "CVE-2024-1234", "vendor": "Apache", "product": "HTTP Server",
             "name": "Apache RCE", "date_added": "2024-01-20"},
            {"cve_id": "CVE-2024-5678", "vendor": "Microsoft", "product": "Exchange",
             "name": "Exchange SSRF", "date_added": "2024-01-20"},
        ]
        embed = notifier._build_kev_embed(entries)
        assert "2 New Actively Exploited" in embed["title"]
        assert embed["color"] == 0xFF0000
        assert "CVE-2024-1234" in embed["description"]
        assert "CVE-2024-5678" in embed["description"]
        assert "CISA" in embed["footer"]["text"]

    def test_build_kev_embed_truncates(self):
        entries = [
            {"cve_id": f"CVE-2024-{i:04d}", "vendor": "V", "product": "P",
             "name": "Vuln", "date_added": "2024-01-20"}
            for i in range(20)
        ]
        embed = notifier._build_kev_embed(entries)
        assert "...and 5 more" in embed["description"]

    @patch("bbradar.modules.notifier._send_discord", return_value=True)
    @patch("bbradar.modules.notifier._send_desktop", return_value=True)
    @patch("bbradar.modules.notifier.get_status", return_value={
        "discord": {"configured": True},
        "desktop": {"enabled": True},
    })
    @patch("bbradar.modules.notifier.log_action")
    def test_notify_new_kev(self, mock_log, mock_status, mock_desktop, mock_discord):
        entries = [
            {"cve_id": "CVE-2024-1234", "vendor": "Apache", "product": "Struts",
             "name": "RCE", "date_added": "2024-01-20"},
        ]
        result = notifier.notify_new_kev(entries)
        assert result["discord"] is True
        assert result["desktop"] is True
        assert result["count"] == 1
        mock_discord.assert_called_once()
        mock_desktop.assert_called_once()

    @patch("bbradar.modules.notifier._send_discord", return_value=True)
    @patch("bbradar.modules.notifier.get_status", return_value={
        "discord": {"configured": True},
        "desktop": {"enabled": False},
    })
    @patch("bbradar.modules.notifier.log_action")
    def test_notify_new_kev_discord_only(self, mock_log, mock_status, mock_discord):
        entries = [
            {"cve_id": "CVE-2024-1234", "vendor": "V", "product": "P",
             "name": "N", "date_added": "2024-01-20"},
        ]
        result = notifier.notify_new_kev(entries)
        assert result["discord"] is True
        assert result["desktop"] is False

    def test_notify_new_kev_empty(self):
        result = notifier.notify_new_kev([])
        assert result["count"] == 0
        assert result["discord"] is False

    @patch("bbradar.modules.notifier.get_status", return_value={
        "discord": {"configured": False},
        "desktop": {"enabled": False},
    })
    @patch("bbradar.modules.notifier.log_action")
    def test_notify_new_kev_no_channels(self, mock_log, mock_status):
        entries = [{"cve_id": "CVE-2024-1234", "vendor": "V", "product": "P",
                    "name": "N", "date_added": "2024-01-20"}]
        result = notifier.notify_new_kev(entries)
        assert result["discord"] is False
        assert result["desktop"] is False


# ═══════════════════════════════════════════════════════════════════
# Tests: Sync All integration
# ═══════════════════════════════════════════════════════════════════

class TestSyncAllIntegration:
    def test_sync_all_includes_new_sources(self, tmp_db):
        """sync_all should recognize cve, kev, epss as valid sources."""
        with patch("bbradar.modules.knowledgebase.sync_cve") as mock_cve, \
             patch("bbradar.modules.knowledgebase.sync_kev") as mock_kev, \
             patch("bbradar.modules.knowledgebase.sync_epss") as mock_epss:
            mock_cve.return_value = {"source": "cve", "status": "skipped", "records": 0}
            mock_kev.return_value = {"source": "kev", "status": "skipped", "records": 0}
            mock_epss.return_value = {"source": "epss", "status": "skipped", "records": 0}

            results = knowledgebase.sync_all(
                sources=["cve", "kev", "epss"], db_path=tmp_db,
            )
            assert len(results) == 3
            sources = [r["source"] for r in results]
            assert "cve" in sources
            assert "kev" in sources
            assert "epss" in sources

    def test_sync_all_default_includes_new_sources(self, tmp_db):
        """Default sync_all (no sources specified) should include new sources."""
        # Just verify that the sources list includes the new ones
        from bbradar.modules.knowledgebase import SOURCES
        assert "cve" in SOURCES
        assert "kev" in SOURCES
        assert "epss" in SOURCES


# ═══════════════════════════════════════════════════════════════════
# Tests: Database migration
# ═══════════════════════════════════════════════════════════════════

class TestDBMigration:
    def test_new_tables_created(self, tmp_db):
        """Verify all three new tables exist after init_db."""
        with get_connection(tmp_db) as conn:
            for table in ("kb_cve", "kb_kev", "kb_epss"):
                row = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    (table,)
                ).fetchone()
                assert row is not None, f"Table {table} does not exist"

    def test_kb_cve_schema(self, tmp_db):
        """Verify kb_cve table has all expected columns."""
        with get_connection(tmp_db) as conn:
            info = conn.execute("PRAGMA table_info(kb_cve)").fetchall()
            columns = {row["name"] for row in info}
            expected = {"cve_id", "description", "cvss_v31_score", "cvss_v31_vector",
                        "cvss_v31_severity", "cwe_ids", "affected_products",
                        "references", "published_at", "modified_at", "synced_at"}
            assert expected.issubset(columns)

    def test_kb_kev_schema(self, tmp_db):
        with get_connection(tmp_db) as conn:
            info = conn.execute("PRAGMA table_info(kb_kev)").fetchall()
            columns = {row["name"] for row in info}
            expected = {"cve_id", "vendor", "product", "name", "description",
                        "date_added", "due_date", "required_action",
                        "known_ransomware", "notes", "synced_at"}
            assert expected.issubset(columns)

    def test_kb_epss_schema(self, tmp_db):
        with get_connection(tmp_db) as conn:
            info = conn.execute("PRAGMA table_info(kb_epss)").fetchall()
            columns = {row["name"] for row in info}
            expected = {"cve_id", "epss_score", "percentile", "model_version",
                        "score_date", "synced_at"}
            assert expected.issubset(columns)
