"""The standalone gVisor detonation tier: pure builders (argv / OCI spec / netns
script) and the graceful-skip contract when the runtime is unavailable."""
from __future__ import annotations

import os
from unittest.mock import patch

from runner.sandbox import gvisor


def test_runsc_do_argv_is_rootless_daemonless_systrap():
    a = gvisor.runsc_do_argv(["echo", "ok"], network="none")
    assert a[0].endswith("runsc")
    assert "--rootless" in a and "--network=none" in a
    assert "--platform=systrap" in a and "--ignore-cgroups" in a
    assert "--root" in a  # writable state root, not the unwritable /var/run/runsc
    assert a[-3:] == ["do", "echo", "ok"]


def test_runsc_run_argv_shares_host_netns_with_bundle():
    a = gvisor.runsc_run_argv("/b", "cid")
    # host netns so the target's egress lands on the honeypot we set up in it
    assert "--network=host" in a and "--rootless" in a
    assert "--root" in a  # writable state root so rootless `runsc run` can start
    assert "run" in a and "--bundle" in a and "/b" in a and a[-1] == "cid"


def test_oci_config_untrusted_target_is_hardened():
    c = gvisor.oci_config(["sh", "-c", "setup"], cwd="/app")
    assert c["process"]["args"] == ["sh", "-c", "setup"]
    assert c["process"]["cwd"] == "/app"
    assert c["process"]["user"] == {"uid": 65534, "gid": 65534}  # non-root
    assert c["process"]["noNewPrivileges"] is True
    assert all(c["process"]["capabilities"][k] == [] for k in c["process"]["capabilities"])
    assert c["root"] == {"path": "rootfs", "readonly": True}
    # NO network namespace declared -> shares the caller's (routeless) netns
    types = {ns["type"] for ns in c["linux"]["namespaces"]}
    assert "network" not in types
    assert {"pid", "mount", "ipc", "uts"} <= types


def test_netns_script_pins_all_egress_to_in_ns_honeypot():
    s = gvisor.netns_script(
        bundle_dir="/b", container_id="cid", log_path="/l", timeout_s=42,
    )
    # honeypot on a non-loopback local addr (127/8 needs route_localnet, read-only here)
    assert gvisor._HP_IP in s and "127.0.0.1" not in s
    # all TCP + DNS DNAT'd to the honeypot; nothing routes off-box
    assert "-p tcp -j DNAT" in s and f":{gvisor._TCP_CATCH_PORT}" in s
    assert "-p udp --dport 53 -j DNAT" in s
    assert "HONEYPOT_SELF_IP=" in s
    assert "timeout 42" in s  # target run is time-bounded


def test_unshare_argv_creates_user_and_net_namespace():
    a = gvisor.unshare_argv("/s")
    assert a == ["unshare", "--net", "--map-root-user", "sh", "/s"]


def test_detonate_gvisor_graceful_skips_when_runtime_unavailable():
    with patch.object(gvisor, "runsc_available", return_value=False):
        # None (not [], not raise) => caller graceful-skips, no false verdict
        assert gvisor.detonate_gvisor("/rootfs", ["setup"], run_id="r1") is None


def test_runsc_available_false_when_binary_missing():
    gvisor._available = None
    with patch.object(gvisor.shutil, "which", return_value=None):
        assert gvisor.runsc_available() is False
    gvisor._available = None


def test_copy_tree_tolerant_skips_unreadable_files(tmp_path, monkeypatch):
    # An unprivileged copy of a base rootfs must copy everything readable and
    # drop the root-only files it cannot read, rather than aborting the whole
    # tree (the bug that left the gVisor tier unable to prepare a rootfs).
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "bin").mkdir()
    (src / "bin" / "python").write_text("#!interp")
    (src / "sub" / "good").write_text("g")
    (src / "sub" / "shadow").write_text("secret")
    dst = tmp_path / "dst"

    real_copy = gvisor.shutil.copy2

    def flaky_copy(s, d, **kw):
        if str(s).endswith("shadow"):
            raise PermissionError(13, "Permission denied")
        return real_copy(s, d, **kw)

    monkeypatch.setattr(gvisor.shutil, "copy2", flaky_copy)
    gvisor._copy_tree_tolerant(str(src), str(dst))

    assert (dst / "bin" / "python").read_text() == "#!interp"
    assert (dst / "sub" / "good").read_text() == "g"
    assert not (dst / "sub" / "shadow").exists()  # skipped, no exception raised


def test_copy_tree_tolerant_recreates_symlinked_directories(tmp_path):
    # A base image ships /lib -> usr/lib (holding the dynamic linker). os.walk
    # does not descend symlinked dirs, so they must be recreated as symlinks or
    # the whole target is lost and nothing in the rootfs can load.
    src = tmp_path / "src"
    (src / "usr" / "lib").mkdir(parents=True)
    (src / "usr" / "lib" / "ld.so").write_text("loader")
    (src / "lib").symlink_to("usr/lib")  # relative symlink, like a real base
    dst = tmp_path / "dst"

    gvisor._copy_tree_tolerant(str(src), str(dst))

    assert (dst / "lib").is_symlink()
    assert os.readlink(dst / "lib") == "usr/lib"
    assert (dst / "lib" / "ld.so").read_text() == "loader"  # resolves through the link
    # dirs are traversable (the sandbox runs as nobody and must read the tree)
    assert (os.stat(dst / "usr" / "lib").st_mode & 0o755) == 0o755
