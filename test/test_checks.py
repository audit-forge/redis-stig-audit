import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from checks.auth import RedisAuthChecker
from checks.config import RedisConfigChecker
from checks.container import RedisContainerChecker
from checks.runtime import RedisRuntimeChecker


class FakeRunner:
    def __init__(
        self,
        cfg=None,
        acl=None,
        info_sections=None,
        mode="direct",
        container=None,
        pod=None,
        namespace="default",
        docker_inspect=None,
        pod_inspect_data=None,
    ):
        self.cfg = cfg or {}
        self.acl = acl or []
        self.info_sections = info_sections or {}
        self.mode = mode
        self.container = container
        self.pod = pod
        self.namespace = namespace
        self._docker_inspect = docker_inspect  # dict (first element) or None
        self._pod_inspect = pod_inspect_data   # full kubectl get pod dict or None
        self.last_error = None
        self.command_log = []

    def config_get(self, *patterns):
        return {k: v for k, v in self.cfg.items() if k in patterns}

    def acl_list(self):
        return list(self.acl)

    def info(self, *sections):
        data = {}
        for section in sections:
            data.update(self.info_sections.get(section, {}))
        return data

    def container_inspect(self):
        return self._docker_inspect or {}

    def pod_inspect(self):
        return self._pod_inspect or {}

    def test_connection(self):
        return True

    def snapshot(self):
        return {
            "config": self.cfg,
            "acl_list": self.acl,
            "info_server": self.info_sections.get("server", {}),
            "info_replication": self.info_sections.get("replication", {}),
            "info_persistence": self.info_sections.get("persistence", {}),
            "command_log_tail": [],
            "last_error": None,
            "container_meta": self._docker_inspect or self._pod_inspect,
        }


class CheckCoverageTests(unittest.TestCase):
    def test_hardened_profile_yields_no_failures(self):
        runner = FakeRunner(
            cfg={
                "protected-mode": "yes",
                "bind": "127.0.0.1 -::1",
                "port": "0",
                "tls-port": "6379",
                "tls-replication": "yes",
                "tls-cluster": "yes",
                "appendonly": "yes",
                "save": "900 1",
                "aclfile": "/etc/redis/users.acl",
                "loglevel": "notice",
                "logfile": "",
                "syslog-enabled": "no",
            },
            acl=["user default on sanitize-payload ~* &* -@all +get +set +ping >hashed-secret"],
            info_sections={
                "server": {"redis_mode": "standalone", "process_supervised": "systemd"},
                "replication": {"role": "master"},
                "persistence": {"aof_enabled": "1", "rdb_last_bgsave_status": "ok"},
            },
        )
        results = []
        for checker in (RedisConfigChecker, RedisRuntimeChecker, RedisAuthChecker):
            results.extend(checker(runner).run())

        failing = [r for r in results if r.status.value in {"FAIL", "ERROR"}]
        self.assertEqual([], failing)

    def test_insecure_profile_surfaces_critical_findings(self):
        runner = FakeRunner(
            cfg={
                "protected-mode": "no",
                "bind": "0.0.0.0",
                "port": "6379",
                "tls-port": "0",
                "tls-replication": "no",
                "appendonly": "no",
                "save": "",
                "aclfile": "",
                "loglevel": "",
                "logfile": "",
                "syslog-enabled": "no",
            },
            acl=["user default on nopass ~* &* +@all"],
            info_sections={
                "server": {"redis_mode": "standalone", "process_supervised": "no"},
                "replication": {"role": "replica"},
                "persistence": {"aof_enabled": "0", "rdb_last_bgsave_status": "err"},
            },
        )
        results = []
        for checker in (RedisConfigChecker, RedisRuntimeChecker, RedisAuthChecker):
            results.extend(checker(runner).run())

        by_id = {r.check_id: r for r in results}
        self.assertEqual("FAIL", by_id["RD-AUTH-001"].status.value)
        self.assertEqual("FAIL", by_id["RD-CFG-002"].status.value)
        self.assertEqual("WARN", by_id["RD-CFG-008"].status.value)

    def test_cli_json_shape_contains_summary_and_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            outfile = Path(tmp) / "results.json"
            proc = subprocess.run(
                [
                    "python3",
                    "audit.py",
                    "--mode",
                    "direct",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "6399",
                    "--json",
                    str(outfile),
                    "--quiet",
                ],
                cwd=Path(__file__).resolve().parents[1],
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, proc.returncode, msg=proc.stderr)
            document = json.loads(outfile.read_text())
            self.assertIn("summary", document)
            self.assertIn("snapshot", document)
            self.assertIn("results", document)
            self.assertIn("risk_posture", document["summary"])
            self.assertIn("command_log_tail", document["snapshot"])


# ---------------------------------------------------------------------------
# Hardened docker inspect fixture
# ---------------------------------------------------------------------------
_HARDENED_DOCKER_INSPECT = {
    "Config": {"User": "999"},
    "HostConfig": {
        "Privileged": False,
        "CapAdd": None,
        "CapDrop": ["ALL"],
        "ReadonlyRootfs": True,
        "Memory": 536870912,   # 512 MiB
        "NanoCpus": 1000000000,  # 1 CPU
        "NetworkMode": "bridge",
        "PidMode": "",
        "IpcMode": "private",
    },
}

# Insecure docker inspect fixture — every control violated
_INSECURE_DOCKER_INSPECT = {
    "Config": {"User": ""},
    "HostConfig": {
        "Privileged": True,
        "CapAdd": ["SYS_ADMIN", "NET_ADMIN"],
        "CapDrop": [],
        "ReadonlyRootfs": False,
        "Memory": 0,
        "NanoCpus": 0,
        "NetworkMode": "host",
        "PidMode": "host",
        "IpcMode": "host",
    },
}

# Hardened kubectl pod fixture
_HARDENED_POD_INSPECT = {
    "spec": {
        "hostNetwork": False,
        "hostPID": False,
        "hostIPC": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 999},
        "containers": [
            {
                "name": "redis",
                "securityContext": {
                    "privileged": False,
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"], "add": []},
                },
                "resources": {
                    "limits": {"memory": "512Mi", "cpu": "1"},
                },
            }
        ],
    }
}

# Insecure kubectl pod fixture — every control violated
_INSECURE_POD_INSPECT = {
    "spec": {
        "hostNetwork": True,
        "hostPID": True,
        "hostIPC": True,
        "securityContext": {},
        "containers": [
            {
                "name": "redis",
                "securityContext": {
                    "privileged": True,
                    "allowPrivilegeEscalation": True,
                    "readOnlyRootFilesystem": False,
                    "capabilities": {"drop": [], "add": ["SYS_ADMIN"]},
                },
                "resources": {},
            }
        ],
    }
}


class ContainerCheckerDockerTests(unittest.TestCase):
    def _results(self, inspect_data):
        runner = FakeRunner(mode="docker", container="redis-test", docker_inspect=inspect_data)
        return {r.check_id: r for r in RedisContainerChecker(runner).run()}

    def test_hardened_docker_all_pass(self):
        by_id = self._results(_HARDENED_DOCKER_INSPECT)
        failing = [r for r in by_id.values() if r.status.value in {"FAIL", "ERROR", "WARN"}]
        self.assertEqual([], failing, msg=[(r.check_id, r.status, r.actual) for r in failing])

    def test_insecure_docker_surfaces_all_failures(self):
        by_id = self._results(_INSECURE_DOCKER_INSPECT)
        self.assertEqual("FAIL", by_id["RD-CONT-001"].status.value, "non-root check")
        self.assertEqual("FAIL", by_id["RD-CONT-002"].status.value, "privileged check")
        self.assertEqual("FAIL", by_id["RD-CONT-003"].status.value, "dangerous caps check")
        self.assertIn(by_id["RD-CONT-004"].status.value, {"WARN", "FAIL"}, "readonly rootfs")
        self.assertEqual("FAIL", by_id["RD-CONT-005"].status.value, "resource limits check")
        self.assertEqual("FAIL", by_id["RD-CONT-006"].status.value, "host namespaces check")

    def test_direct_mode_all_skip(self):
        runner = FakeRunner(mode="direct")
        results = RedisContainerChecker(runner).run()
        self.assertTrue(all(r.status.value == "SKIP" for r in results))
        self.assertEqual(6, len(results))

    def test_docker_inspect_failure_all_error(self):
        runner = FakeRunner(mode="docker", container="redis-test", docker_inspect=None)
        results = RedisContainerChecker(runner).run()
        self.assertTrue(all(r.status.value == "ERROR" for r in results))
        self.assertEqual(6, len(results))

    def test_dangerous_cap_add_only_no_drop_is_fail(self):
        inspect = {
            "Config": {"User": "999"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": ["NET_RAW"],
                "CapDrop": [],
                "ReadonlyRootfs": True,
                "Memory": 512 * 1024 * 1024,
                "NanoCpus": 1_000_000_000,
                "NetworkMode": "bridge",
                "PidMode": "",
                "IpcMode": "private",
            },
        }
        by_id = self._results(inspect)
        self.assertEqual("FAIL", by_id["RD-CONT-003"].status.value)

    def test_partial_resource_limits_is_warn(self):
        inspect = {
            "Config": {"User": "999"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "ReadonlyRootfs": True,
                "Memory": 512 * 1024 * 1024,
                "NanoCpus": 0,   # CPU limit not set
                "NetworkMode": "bridge",
                "PidMode": "",
                "IpcMode": "private",
            },
        }
        by_id = self._results(inspect)
        self.assertEqual("WARN", by_id["RD-CONT-005"].status.value)

    def test_evidence_captured_for_each_check(self):
        by_id = self._results(_HARDENED_DOCKER_INSPECT)
        for r in by_id.values():
            self.assertTrue(len(r.evidence) >= 1, f"{r.check_id} has no evidence")


class ContainerCheckerKubectlTests(unittest.TestCase):
    def _results(self, pod_data):
        runner = FakeRunner(
            mode="kubectl",
            pod="redis-0",
            namespace="prod",
            pod_inspect_data=pod_data,
        )
        return {r.check_id: r for r in RedisContainerChecker(runner).run()}

    def test_hardened_kubectl_all_pass(self):
        by_id = self._results(_HARDENED_POD_INSPECT)
        failing = [r for r in by_id.values() if r.status.value in {"FAIL", "ERROR", "WARN"}]
        self.assertEqual([], failing, msg=[(r.check_id, r.status, r.actual) for r in failing])

    def test_insecure_kubectl_surfaces_all_failures(self):
        by_id = self._results(_INSECURE_POD_INSPECT)
        self.assertIn(by_id["RD-CONT-001"].status.value, {"FAIL", "WARN"}, "non-root check")
        self.assertEqual("FAIL", by_id["RD-CONT-002"].status.value, "privileged check")
        self.assertEqual("FAIL", by_id["RD-CONT-003"].status.value, "dangerous caps check")
        self.assertIn(by_id["RD-CONT-004"].status.value, {"WARN", "FAIL"}, "readonly rootfs")
        self.assertEqual("FAIL", by_id["RD-CONT-005"].status.value, "resource limits check")
        self.assertEqual("FAIL", by_id["RD-CONT-006"].status.value, "host namespaces check")

    def test_kubectl_inspect_failure_all_error(self):
        runner = FakeRunner(mode="kubectl", pod="redis-0", namespace="prod", pod_inspect_data=None)
        results = RedisContainerChecker(runner).run()
        self.assertTrue(all(r.status.value == "ERROR" for r in results))
        self.assertEqual(6, len(results))


if __name__ == "__main__":
    unittest.main()
