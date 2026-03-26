from __future__ import annotations

from .base import BaseChecker, CheckResult, Severity, Status


class RedisRuntimeChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        info = self.runner.info("server")
        replication = self.runner.info("replication")
        persistence = self.runner.info("persistence")
        results = []

        process_supervised = info.get("process_supervised", "unknown")
        redis_mode = info.get("redis_mode", "unknown")
        results.append(
            CheckResult(
                check_id="RD-RT-001",
                title="Collect Redis runtime server metadata for audit traceability",
                status=Status.PASS if info else Status.ERROR,
                severity=Severity.INFO,
                benchmark_control_id="8.0",
                cis_id="draft-8.0",
                fedramp_control="AU-3",
                nist_800_53_controls=["AU-3"],
                description="Runtime metadata helps support repeatable annual audit evidence and traceability.",
                rationale="Assessments should capture enough environment metadata to make findings reproducible and reviewable later.",
                actual=f"redis_mode={redis_mode}, process_supervised={process_supervised}",
                expected="runtime metadata available",
                remediation="Ensure the scanner can collect server metadata through INFO or equivalent runtime evidence.",
                references=["Redis INFO documentation"],
                category="Runtime",
                evidence_type="runtime-config",
                evidence=[self.evidence("info.server", {"redis_mode": redis_mode, "process_supervised": process_supervised}, "redis-cli INFO server")],
            )
        )

        role = replication.get("role", "unknown")
        results.append(
            CheckResult(
                check_id="RD-RT-002",
                title="Capture replication role for topology-aware assessment",
                status=Status.PASS if role != "unknown" else Status.WARN,
                severity=Severity.LOW,
                benchmark_control_id="5.1",
                cis_id="draft-5.1",
                fedramp_control="SC-7",
                nist_800_53_controls=["SC-7", "SC-8"],
                description="Replication role should be known so replication-path controls can be assessed accurately.",
                rationale="Redis topology changes the threat model and determines which replication transport controls matter.",
                actual=role,
                expected="master/replica role identified",
                remediation="Collect and review Redis replication topology before evaluating replication security controls.",
                references=["Redis INFO documentation"],
                category="Runtime",
                evidence_type="runtime-config",
                evidence=[self.evidence("info.replication.role", role, "redis-cli INFO replication")],
            )
        )

        last_bgsave_status = persistence.get("rdb_last_bgsave_status", "unknown")
        aof_enabled = persistence.get("aof_enabled", "unknown")
        results.append(
            CheckResult(
                check_id="RD-RT-003",
                title="Capture persistence runtime health for recoverability evidence",
                status=Status.PASS if persistence else Status.WARN,
                severity=Severity.LOW,
                benchmark_control_id="4.1",
                cis_id="draft-4.1b",
                fedramp_control="CP-9",
                nist_800_53_controls=["CP-9", "AU-3"],
                description="Persistence runtime telemetry helps distinguish an intended persistence design from a failing one.",
                rationale="Configuration alone is insufficient if persistence jobs are failing in practice.",
                actual=f"aof_enabled={aof_enabled}, rdb_last_bgsave_status={last_bgsave_status}",
                expected="persistence telemetry available for review",
                remediation="Collect and review persistence runtime health alongside configuration settings.",
                references=["Redis INFO persistence documentation"],
                category="Persistence",
                evidence_type="runtime-config",
                evidence=[self.evidence("info.persistence", {"aof_enabled": aof_enabled, "rdb_last_bgsave_status": last_bgsave_status}, "redis-cli INFO persistence")],
            )
        )

        return results
