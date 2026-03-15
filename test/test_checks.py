import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from checks.auth import RedisAuthChecker
from checks.config import RedisConfigChecker
from checks.runtime import RedisRuntimeChecker


class FakeRunner:
    def __init__(self, cfg=None, acl=None, info_sections=None):
        self.cfg = cfg or {}
        self.acl = acl or []
        self.info_sections = info_sections or {}
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


if __name__ == "__main__":
    unittest.main()
