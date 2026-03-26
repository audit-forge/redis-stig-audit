from __future__ import annotations

from .base import BaseChecker, CheckResult, Severity, Status


class RedisConfigChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        cfg = self.runner.config_get(
            "protected-mode",
            "bind",
            "port",
            "tls-port",
            "tls-replication",
            "tls-cluster",
            "appendonly",
            "appenddirname",
            "save",
            "dir",
            "dbfilename",
            "aclfile",
            "loglevel",
            "logfile",
            "syslog-enabled",
        )
        acl_users = self.runner.acl_list()
        replication = self.runner.info("replication")
        results = []

        protected = cfg.get("protected-mode")
        results.append(
            CheckResult(
                check_id="RD-CFG-001",
                title="Keep protected mode enabled unless compensating controls exist",
                status=Status.PASS if protected == "yes" else Status.FAIL if protected else Status.ERROR,
                severity=Severity.HIGH,
                benchmark_control_id="2.4",
                cis_id="draft-2.4",
                fedramp_control="SC-7",
                nist_800_53_controls=["SC-7"],
                description="Redis protected mode helps guard against unintentionally exposed instances.",
                rationale="Protected mode is one of Redis's built-in safeguards against accidental exposure and unsafe startup defaults.",
                actual=protected or "unavailable",
                expected="yes",
                remediation="Set `protected-mode yes` unless documented compensating controls are in place.",
                references=["Redis security docs: protected mode"],
                category="Configuration",
                evidence_type="runtime-config",
                evidence=[self.evidence("config.protected-mode", protected or "unavailable", "redis-cli CONFIG GET protected-mode")],
            )
        )

        bind = cfg.get("bind", "")
        bind_safe = bind not in ("", "0.0.0.0", "*")
        results.append(
            CheckResult(
                check_id="RD-CFG-002",
                title="Bind Redis only to trusted interfaces",
                status=Status.PASS if bind_safe else Status.FAIL,
                severity=Severity.CRITICAL,
                benchmark_control_id="2.5",
                cis_id="draft-2.5",
                fedramp_control="SC-7",
                nist_800_53_controls=["SC-7"],
                description="Broad network binding increases the risk of unintended Redis exposure.",
                rationale="Redis assumes a trusted network path. Broad bind scope increases the chance of unauthorized reachability.",
                actual=bind or "not explicitly set",
                expected="loopback or explicitly trusted interface(s)",
                remediation="Set `bind` to loopback or trusted interface addresses and pair with network-layer restrictions.",
                references=["Redis security docs: trusted clients, firewalling, bind"],
                category="Configuration",
                evidence_type="network-exposure",
                evidence=[self.evidence("config.bind", bind or "not explicitly set", "redis-cli CONFIG GET bind")],
            )
        )

        tls_port = cfg.get("tls-port", "0")
        plaintext_port = cfg.get("port", "6379")
        results.append(
            CheckResult(
                check_id="RD-CFG-003",
                title="Enable TLS where Redis traffic crosses trust boundaries",
                status=Status.PASS if tls_port not in ("", "0") else Status.WARN,
                severity=Severity.MEDIUM,
                benchmark_control_id="3.1",
                cis_id="draft-3.1",
                fedramp_control="SC-8",
                nist_800_53_controls=["SC-8"],
                description="TLS should protect Redis traffic when confidentiality or compliance requirements apply.",
                rationale="Unencrypted Redis traffic can expose credentials and data when networks are not fully trusted.",
                actual=f"tls-port={tls_port}, port={plaintext_port}",
                expected="non-zero TLS port when transport encryption is required",
                remediation="Configure `tls-port` and related certificate settings; consider disabling plaintext `port` where appropriate.",
                references=["Redis TLS documentation"],
                category="Transport Security",
                evidence_type="runtime-config",
                evidence=[self.evidence("config.transport", {"tls-port": tls_port, "port": plaintext_port}, "redis-cli CONFIG GET tls-port port")],
            )
        )

        default_acl_line = next((line for line in acl_users if line.startswith("user default ")), "")
        default_open = ("nopass" in default_acl_line) or ("+@all" in default_acl_line and " on " in f" {default_acl_line} ")
        acl_status = Status.FAIL if default_open and acl_users else Status.PASS if acl_users else Status.ERROR
        results.append(
            CheckResult(
                check_id="RD-CFG-004",
                title="Restrict default-user broad access and prefer ACL-based least privilege",
                status=acl_status,
                severity=Severity.CRITICAL,
                benchmark_control_id="2.2",
                cis_id="draft-2.2",
                fedramp_control="AC-2",
                nist_800_53_controls=["AC-2", "AC-3", "AC-6"],
                description="The default ACL user should not remain broadly permissive in regulated production deployments.",
                rationale="The default user is frequently the most dangerous over-permission path in lightly hardened Redis deployments.",
                actual=default_acl_line or "ACL LIST unavailable",
                expected="no `nopass` broad default-user access; named least-privilege users preferred",
                remediation="Use ACLs to define named users and remove overly broad default-user access.",
                references=["Redis ACL documentation", "Redis security docs: ACLs preferred"],
                category="Authentication",
                evidence_type="runtime-config",
                evidence=[self.evidence("default_acl", default_acl_line or "unavailable", "redis-cli ACL LIST")],
            )
        )

        dangerous_restricted = False
        if default_acl_line:
            dangerous_restricted = "-@all" in default_acl_line or ("+@all" not in default_acl_line)
        results.append(
            CheckResult(
                check_id="RD-CFG-005",
                title="Restrict dangerous administrative commands",
                status=Status.PASS if dangerous_restricted else Status.FAIL if default_acl_line else Status.ERROR,
                severity=Severity.HIGH,
                benchmark_control_id="2.3",
                cis_id="draft-2.3",
                fedramp_control="CM-7",
                nist_800_53_controls=["CM-7", "AC-6"],
                description="Dangerous commands should not be broadly available to the default or application users.",
                rationale="Redis destructive and administrative commands can materially alter or destroy service state.",
                actual=default_acl_line or "ACL LIST unavailable",
                expected="dangerous commands restricted via ACLs or equivalent approved control",
                remediation="Use ACLs to deny broad administrative command access to default/application users.",
                references=["Redis security docs: command restriction guidance", "Redis ACL documentation"],
                category="Configuration",
                evidence_type="runtime-config",
                evidence=[self.evidence("default_acl", default_acl_line or "unavailable", "redis-cli ACL LIST")],
            )
        )

        appendonly = cfg.get("appendonly", "")
        save = cfg.get("save", "")
        persistence_ok = appendonly == "yes" or bool(save.strip())
        results.append(
            CheckResult(
                check_id="RD-CFG-006",
                title="Configure persistence intentionally",
                status=Status.PASS if persistence_ok else Status.WARN,
                severity=Severity.MEDIUM,
                benchmark_control_id="4.1",
                cis_id="draft-4.1",
                fedramp_control="CP-9",
                nist_800_53_controls=["CP-9"],
                description="Redis persistence settings should be explicitly configured to match recovery and data durability needs.",
                rationale="Persistence posture needs to match data criticality and recovery objectives rather than remain implicit or accidental.",
                actual=f"appendonly={appendonly or 'unset'}, save={save or 'unset'}",
                expected="documented AOF, RDB, both, or explicit decision for ephemeral use",
                remediation="Set and document persistence behavior appropriate to the workload and audit requirements.",
                references=["Redis configuration guidance"],
                category="Persistence",
                evidence_type="runtime-config",
                evidence=[self.evidence("config.persistence", {"appendonly": appendonly or "unset", "save": save or "unset"}, "redis-cli CONFIG GET appendonly save")],
            )
        )

        aclfile = cfg.get("aclfile", "")
        results.append(
            CheckResult(
                check_id="RD-CFG-007",
                title="Persist ACL configuration outside ad hoc runtime state",
                status=Status.PASS if aclfile else Status.WARN,
                severity=Severity.LOW,
                benchmark_control_id="2.2",
                cis_id="draft-2.2b",
                fedramp_control="CM-3",
                nist_800_53_controls=["CM-3", "AC-2"],
                description="ACL configuration should be durable and reviewable rather than existing only as transient runtime state.",
                rationale="Durable ACL configuration supports change control, reviewability, and recovery after restart or redeploy.",
                actual=aclfile or "no aclfile configured",
                expected="documented ACL persistence strategy",
                remediation="Use an ACL file or equivalent configuration-as-code approach to preserve and review user policy state.",
                references=["Redis ACL LIST documentation"],
                category="Authentication",
                evidence_type="runtime-config",
                evidence=[self.evidence("config.aclfile", aclfile or "unset", "redis-cli CONFIG GET aclfile")],
            )
        )

        tls_replication = cfg.get("tls-replication", "")
        tls_cluster = cfg.get("tls-cluster", "")
        role = replication.get("role", "unknown")
        replication_over_tls = tls_replication == "yes" or role == "unknown"
        results.append(
            CheckResult(
                check_id="RD-CFG-008",
                title="Secure replication paths with TLS where replication is in use",
                status=Status.PASS if replication_over_tls else Status.WARN,
                severity=Severity.MEDIUM,
                benchmark_control_id="5.1",
                cis_id="draft-5.1",
                fedramp_control="SC-8",
                nist_800_53_controls=["SC-8", "SC-7"],
                description="Replication links should use transport protection when Redis replication traverses potentially observable networks.",
                rationale="A replica topology can silently expand the exposure of credentials and data if replication links remain unencrypted.",
                actual=f"role={role}, tls-replication={tls_replication or 'unset'}, tls-cluster={tls_cluster or 'unset'}",
                expected="replicated deployments use TLS for replication and cluster links",
                remediation="Set `tls-replication yes` and `tls-cluster yes` where replication or clustering is used across trust boundaries.",
                references=["Redis TLS documentation", "Redis replication documentation"],
                category="Transport Security",
                evidence_type="runtime-config",
                evidence=[self.evidence("config.replication_tls", {"role": role, "tls-replication": tls_replication or "unset", "tls-cluster": tls_cluster or "unset"}, "redis-cli INFO replication && redis-cli CONFIG GET tls-replication tls-cluster")],
            )
        )

        plaintext_exposed = tls_port not in ("", "0") and plaintext_port not in ("", "0")
        results.append(
            CheckResult(
                check_id="RD-CFG-009",
                title="Disable plaintext Redis listeners when a TLS-only posture is required",
                status=Status.WARN if plaintext_exposed else Status.PASS,
                severity=Severity.MEDIUM,
                benchmark_control_id="3.1",
                cis_id="draft-3.1b",
                fedramp_control="SC-8",
                nist_800_53_controls=["SC-8"],
                description="Enabling TLS without disabling plaintext listeners may leave a weaker parallel access path available.",
                rationale="Dual-stack transport can be acceptable, but a compliance-focused environment should make the plaintext exception explicit.",
                actual=f"tls-port={tls_port}, port={plaintext_port}",
                expected="port 0 when a TLS-only posture is required",
                remediation="If the environment requires encrypted-only Redis access, set `port 0` after validating all clients use TLS.",
                references=["Redis TLS documentation"],
                category="Transport Security",
                evidence_type="runtime-config",
                evidence=[self.evidence("config.transport", {"tls-port": tls_port, "port": plaintext_port}, "redis-cli CONFIG GET tls-port port")],
            )
        )

        loglevel = cfg.get("loglevel", "")
        logfile = cfg.get("logfile", "")
        syslog_enabled = cfg.get("syslog-enabled", "")
        logging_intentional = bool(loglevel) and (bool(logfile) or syslog_enabled == "yes" or logfile == "")
        results.append(
            CheckResult(
                check_id="RD-CFG-010",
                title="Configure Redis logging intentionally for operational review and evidence retention",
                status=Status.PASS if logging_intentional else Status.WARN,
                severity=Severity.LOW,
                benchmark_control_id="4.3",
                cis_id="draft-4.3",
                fedramp_control="AU-2",
                nist_800_53_controls=["AU-2", "AU-12"],
                description="Redis logging should be configured deliberately so events can feed operations and audit workflows.",
                rationale="Assessors need a clear logging posture, even when containerized Redis writes to stdout/stderr rather than a traditional logfile.",
                actual=f"loglevel={loglevel or 'unset'}, logfile={logfile if logfile != '' else 'stdout/stderr'}, syslog-enabled={syslog_enabled or 'unset'}",
                expected="documented log destination and adequate operational verbosity",
                remediation="Document whether Redis logs to stdout/stderr, a logfile, or syslog; centralize container logs where audit retention is required.",
                references=["Redis configuration guidance", "Container logging guidance"],
                category="Logging",
                evidence_type="runtime-config",
                evidence=[self.evidence("config.logging", {"loglevel": loglevel or "unset", "logfile": logfile if logfile != "" else "stdout/stderr", "syslog-enabled": syslog_enabled or "unset"}, "redis-cli CONFIG GET loglevel logfile syslog-enabled")],
            )
        )

        return results
