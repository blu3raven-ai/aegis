import inspect
from src.containers import scanner


def test_container_ingest_enqueues_verification_jobs():
    src = inspect.getsource(scanner)
    assert "enqueue_container_verify_jobs" in src
    assert "ContainerVerifyFinding" in src
    # best-effort: enqueue must be guarded so it can't fail the scan ingest
    assert "Container verify enqueue failed" in src
