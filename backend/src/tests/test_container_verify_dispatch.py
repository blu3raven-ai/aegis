from unittest.mock import patch
from src.containers import verify_dispatch as vd


def _finding(fid="1", cve="CVE-9"):
    return vd.ContainerVerifyFinding(
        finding_id=fid, asset_id="a1", external_ref="oci:acme/app",
        package="libfoo", version="2.0.0", cve=cve,
        image_name="acme/app", image_tag="1.2.3",
    )


def test_no_jobs_when_byo_llm_disabled():
    with patch.object(vd, "_build_verification_env", return_value={}):
        assert vd.enqueue_container_verify_jobs(org="o", run_id="r", findings=[_finding()]) == []


def test_enqueues_job_with_targets_when_llm_enabled():
    seen = {}
    def _cap(**kw):
        seen.update(kw); return {"id": "job1"}
    with patch.object(vd, "_build_verification_env", return_value={"LLM_API_KEY": "k"}), \
         patch("src.runner.jobs.create_job", side_effect=_cap):
        ids = vd.enqueue_container_verify_jobs(org="o", run_id="r", findings=[_finding()])
    assert ids == ["job1"]
    assert seen["job_type"] == "container_verification"
    import json
    targets = json.loads(seen["env_vars"]["CONTAINER_VERIFY_TARGETS"])
    assert targets[0]["finding_id"] == "1" and targets[0]["cve"] == "CVE-9"


def test_skips_findings_without_cve():
    with patch.object(vd, "_build_verification_env", return_value={"LLM_API_KEY": "k"}), \
         patch("src.runner.jobs.create_job", side_effect=lambda **kw: {"id": "x"}):
        assert vd.enqueue_container_verify_jobs(org="o", run_id="r", findings=[_finding(cve=None)]) == []
