from src.dependencies.normalizer import normalize_grype_output


SAMPLE_GRYPE_OUTPUT = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2021-23337",
                "severity": "High",
                "description": "Lodash prototype pollution",
                "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
                "fix": {"versions": ["4.17.21"], "state": "fixed"},
                "cvss": [{"metrics": {"baseScore": 7.2}}],
                "aliases": ["GHSA-35jh-r3h4-6jhm"],
            },
            "artifact": {
                "name": "lodash",
                "version": "4.17.20",
                "type": "npm",
                "locations": [{"path": "/package-lock.json"}],
            },
        }
    ]
}


def test_normalize_grype_output_basic():
    findings = normalize_grype_output(
        grype_json=SAMPLE_GRYPE_OUTPUT,
        org="myorg",
        repo="myorg/myrepo",
        commit_sha="abc123",
        source_label="grype",
    )
    assert len(findings) == 1
    f = findings[0]
    assert f["repository"]["name"] == "myrepo"
    assert f["repository"]["full_name"] == "myorg/myrepo"
    assert f["dependency"]["package"]["name"] == "lodash"
    assert f["dependency"]["package"]["ecosystem"] == "npm"
    assert f["dependency"]["manifest_path"] == "/package-lock.json"
    assert f["security_advisory"]["ghsa_id"] == "GHSA-35jh-r3h4-6jhm"
    assert f["security_advisory"]["cve_id"] == "CVE-2021-23337"
    assert f["security_advisory"]["severity"] == "high"
    assert f["security_advisory"]["cvss"]["score"] == 7.2
    assert f["security_vulnerability"]["first_patched_version"]["identifier"] == "4.17.21"
    assert f["current_version"] == "4.17.20"
    assert "grype" in f["matched_by"]


def test_normalize_grype_output_empty():
    findings = normalize_grype_output(
        grype_json={"matches": []},
        org="myorg",
        repo="myorg/myrepo",
        commit_sha="abc123",
        source_label="grype",
    )
    assert findings == []


def test_normalize_grype_output_no_fix():
    grype = {
        "matches": [{
            "vulnerability": {
                "id": "CVE-2099-0001",
                "severity": "Medium",
                "description": "No fix available",
                "dataSource": "",
                "fix": {"versions": [], "state": "not-fixed"},
                "cvss": [],
                "aliases": [],
            },
            "artifact": {
                "name": "some-pkg",
                "version": "1.0.0",
                "type": "python",
                "locations": [{"path": "/requirements.txt"}],
            },
        }]
    }
    findings = normalize_grype_output(grype, "org", "org/repo", "sha", "grype")
    assert len(findings) == 1
    assert findings[0]["security_vulnerability"]["first_patched_version"] is None
