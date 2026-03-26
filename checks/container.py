from __future__ import annotations

"""Container-level security checks for Redis (docker/kubectl modes only).

These checks assess controls that are set *outside* Redis — in the container
runtime or orchestrator — and are therefore invisible to redis-cli or CONFIG GET.
All checks emit SKIP status when running in --mode direct.

Control references:
  CIS Docker Benchmark v1.6  (sections 4 and 5)
  CIS Kubernetes Benchmark v1.8  (section 5.2)
  NIST SP 800-190 (Application Container Security Guide)
"""

from .base import BaseChecker, CheckResult, Severity, Status

# Capabilities that should never appear in CapAdd / capabilities.add for a Redis
# container.  Presence of any of these is a FAIL.
_DANGEROUS_CAPS = frozenset(
    {
        "ALL",
        "SYS_ADMIN",
        "NET_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "NET_RAW",
        "SYS_RAWIO",
        "MKNOD",
        "AUDIT_CONTROL",
        "SYS_BOOT",
        "MAC_ADMIN",
        "MAC_OVERRIDE",
    }
)


class RedisContainerChecker(BaseChecker):
    """Assess container-level security controls (docker/kubectl modes only)."""

    def run(self) -> list[CheckResult]:
        mode = getattr(self.runner, "mode", "direct")

        if mode == "direct":
            return self._all_skipped()

        if mode == "docker":
            ctx = self._normalize_docker()
        elif mode == "kubectl":
            ctx = self._normalize_kubectl()
        else:
            return self._all_skipped()

        if ctx is None:
            return self._all_error(mode)

        return [
            self._check_nonroot(ctx),
            self._check_privileged(ctx),
            self._check_caps(ctx),
            self._check_readonly_rootfs(ctx),
            self._check_resource_limits(ctx),
            self._check_host_namespaces(ctx),
        ]

    # ------------------------------------------------------------------
    # Context normalizers — produce a mode-agnostic dict for the checks
    # ------------------------------------------------------------------

    def _normalize_docker(self) -> dict | None:
        data = self.runner.container_inspect()
        if not data:
            return None
        hc = data.get("HostConfig", {})
        cfg = data.get("Config", {})
        inspect_cmd = f"docker inspect {self.runner.container or '<container>'}"
        return {
            "source": "docker",
            "inspect_cmd": inspect_cmd,
            "user": (cfg.get("User") or "").strip(),
            "run_as_non_root": None,  # docker-specific: determined from User field
            "allow_privilege_escalation": None,  # not directly exposed via inspect
            "privileged": bool(hc.get("Privileged", False)),
            "cap_add": [c.upper() for c in (hc.get("CapAdd") or [])],
            "cap_drop": [c.upper() for c in (hc.get("CapDrop") or [])],
            "read_only_rootfs": bool(hc.get("ReadonlyRootfs", False)),
            "memory_limit_set": int(hc.get("Memory", 0)) > 0,
            "cpu_limit_set": int(hc.get("NanoCpus", 0)) > 0,
            "host_network": hc.get("NetworkMode", "") == "host",
            "host_pid": hc.get("PidMode", "") == "host",
            "host_ipc": hc.get("IpcMode", "private") == "host",
            "raw": data,
        }

    def _normalize_kubectl(self) -> dict | None:
        data = self.runner.pod_inspect()
        if not data:
            return None
        spec = data.get("spec", {})
        pod_sc = spec.get("securityContext", {})

        # Pick the Redis container — prefer one with "redis" in the name.
        containers = spec.get("containers", [])
        ctr = next(
            (c for c in containers if "redis" in c.get("name", "").lower()),
            containers[0] if containers else {},
        )
        sc = ctr.get("securityContext", {})
        caps = sc.get("capabilities", {})
        limits = ctr.get("resources", {}).get("limits", {})

        run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
        run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot", False))
        inspect_cmd = (
            f"kubectl get pod -n {self.runner.namespace} {self.runner.pod or '<pod>'} -o json"
        )
        return {
            "source": "kubectl",
            "inspect_cmd": inspect_cmd,
            "user": str(run_as_user) if run_as_user is not None else "",
            "run_as_non_root": run_as_non_root,
            "allow_privilege_escalation": sc.get("allowPrivilegeEscalation"),
            "privileged": bool(sc.get("privileged", False)),
            "cap_add": [c.upper() for c in (caps.get("add") or [])],
            "cap_drop": [c.upper() for c in (caps.get("drop") or [])],
            "read_only_rootfs": bool(sc.get("readOnlyRootFilesystem", False)),
            "memory_limit_set": bool(limits.get("memory")),
            "cpu_limit_set": bool(limits.get("cpu")),
            "host_network": bool(spec.get("hostNetwork", False)),
            "host_pid": bool(spec.get("hostPID", False)),
            "host_ipc": bool(spec.get("hostIPC", False)),
            "raw": data,
        }

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_nonroot(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        user = ctx.get("user", "")
        run_as_non_root = ctx.get("run_as_non_root")

        if src == "docker":
            is_nonroot = bool(user) and user not in ("0", "root")
            actual = f"User={user!r}" if user else "User not set (defaults to root)"
        else:
            run_as_user_int = int(user) if user.isdigit() else None
            is_nonroot = bool(run_as_non_root) or (
                run_as_user_int is not None and run_as_user_int > 0
            )
            parts = []
            if user:
                parts.append(f"runAsUser={user}")
            if run_as_non_root is not None:
                parts.append(f"runAsNonRoot={run_as_non_root}")
            actual = ", ".join(parts) if parts else "runAsUser/runAsNonRoot not set"

        return CheckResult(
            check_id="RD-CONT-001",
            title="Verify Redis process runs as a non-root user",
            status=Status.PASS if is_nonroot else Status.FAIL,
            severity=Severity.HIGH,
            benchmark_control_id="6.1",
            cis_id="draft-6.1",
            fedramp_control="AC-6",
            nist_800_53_controls=["AC-6", "CM-7"],
            description=(
                "The Redis container should run as a non-root user to limit the blast radius "
                "if container isolation is bypassed."
            ),
            rationale=(
                "Running as UID 0 inside a container provides a direct privilege escalation path "
                "to the host if the container runtime or kernel has a vulnerability. "
                "NIST SP 800-190 §4.4.1 requires non-root execution as a baseline control."
            ),
            actual=actual,
            expected="non-zero, non-root UID (e.g. USER redis or runAsUser: 999)",
            remediation=(
                "Set USER <uid> in the Dockerfile or configure runAsUser/runAsNonRoot in "
                "the pod/container securityContext. Use a dedicated redis UID (e.g. 999)."
            ),
            references=[
                "CIS Docker Benchmark v1.6 §4.1",
                "CIS Kubernetes Benchmark v1.8 §5.2.6",
                "NIST SP 800-190 §4.4.1",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[
                self.evidence(
                    f"container.{src}.user",
                    {"user": user, "run_as_non_root": run_as_non_root},
                    ctx["inspect_cmd"],
                )
            ],
        )

    def _check_privileged(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        privileged = ctx.get("privileged", False)
        ape = ctx.get("allow_privilege_escalation")

        if src == "kubectl":
            is_fail = privileged or (ape is True)
            actual_parts = [f"privileged={privileged}"]
            if ape is not None:
                actual_parts.append(f"allowPrivilegeEscalation={ape}")
            actual = ", ".join(actual_parts)
        else:
            is_fail = privileged
            actual = f"Privileged={privileged}"

        return CheckResult(
            check_id="RD-CONT-002",
            title="Verify Redis container does not run in privileged mode",
            status=Status.FAIL if is_fail else Status.PASS,
            severity=Severity.CRITICAL,
            benchmark_control_id="6.2",
            cis_id="draft-6.2",
            fedramp_control="CM-7",
            nist_800_53_controls=["CM-7", "AC-6", "SC-4"],
            description=(
                "Privileged containers have near-unrestricted host access. "
                "Redis should never require privileged mode."
            ),
            rationale=(
                "Privileged mode disables seccomp, AppArmor, SELinux, and capability restrictions, "
                "effectively granting root on the host. There is no legitimate Redis use case "
                "that requires privileged mode."
            ),
            actual=actual,
            expected="privileged=False, allowPrivilegeEscalation=False",
            remediation=(
                "Remove privileged: true from the container spec. "
                "Set allowPrivilegeEscalation: false in the securityContext (Kubernetes)."
            ),
            references=[
                "CIS Docker Benchmark v1.6 §5.4",
                "CIS Kubernetes Benchmark v1.8 §5.2.1",
                "NIST SP 800-190 §4.4.2",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[
                self.evidence(
                    f"container.{src}.privileged",
                    {"privileged": privileged, "allowPrivilegeEscalation": ape},
                    ctx["inspect_cmd"],
                )
            ],
        )

    def _check_caps(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        cap_add = ctx.get("cap_add", [])
        cap_drop = ctx.get("cap_drop", [])

        dangerous_added = sorted(_DANGEROUS_CAPS & set(cap_add))
        drops_all = "ALL" in cap_drop

        if dangerous_added:
            status = Status.FAIL
        elif not drops_all:
            status = Status.WARN
        else:
            status = Status.PASS

        actual = (
            f"cap_add={cap_add or '[]'}, cap_drop={cap_drop or '[]'}"
            + (f" [DANGEROUS: {dangerous_added}]" if dangerous_added else "")
        )

        return CheckResult(
            check_id="RD-CONT-003",
            title="Verify dangerous Linux capabilities are not granted to the Redis container",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="6.3",
            cis_id="draft-6.3",
            fedramp_control="CM-7",
            nist_800_53_controls=["CM-7", "AC-6"],
            description=(
                "Redis does not require elevated Linux capabilities. "
                "Dropping ALL capabilities and adding none is the expected hardened posture."
            ),
            rationale=(
                "Linux capabilities granularly grant root-like privileges. "
                "Capabilities such as SYS_ADMIN, NET_ADMIN, and NET_RAW significantly "
                "expand the container attack surface beyond what Redis requires."
            ),
            actual=actual,
            expected="cap_drop=[ALL], cap_add=[] (or empty)",
            remediation=(
                "Add 'drop: [ALL]' to capabilities in the container securityContext "
                "(or --cap-drop ALL for docker run). Do not add any capabilities unless "
                "a specific, documented operational requirement exists."
            ),
            references=[
                "CIS Docker Benchmark v1.6 §5.3",
                "CIS Kubernetes Benchmark v1.8 §5.2.8",
                "NIST SP 800-190 §4.4.2",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[
                self.evidence(
                    f"container.{src}.capabilities",
                    {"cap_add": cap_add, "cap_drop": cap_drop},
                    ctx["inspect_cmd"],
                )
            ],
        )

    def _check_readonly_rootfs(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        read_only = ctx.get("read_only_rootfs", False)

        return CheckResult(
            check_id="RD-CONT-004",
            title="Verify Redis container root filesystem is mounted read-only",
            status=Status.PASS if read_only else Status.WARN,
            severity=Severity.MEDIUM,
            benchmark_control_id="6.4",
            cis_id="draft-6.4",
            fedramp_control="CM-7",
            nist_800_53_controls=["CM-7", "SC-28"],
            description=(
                "A read-only root filesystem prevents attackers from persisting changes "
                "to the container image layer at runtime."
            ),
            rationale=(
                "If an attacker achieves RCE inside the container, a writable root filesystem "
                "allows them to install backdoors, modify Redis binaries, or alter configuration. "
                "Redis data should live on a dedicated mount, not the root filesystem."
            ),
            actual=f"ReadonlyRootfs={read_only}",
            expected="ReadonlyRootfs=True",
            remediation=(
                "Set readOnlyRootFilesystem: true in the container securityContext "
                "(or --read-only for docker run). "
                "Mount /data and /tmp as writable volumes if Redis needs them."
            ),
            references=[
                "CIS Docker Benchmark v1.6 §5.12",
                "CIS Kubernetes Benchmark v1.8 §5.2.4",
                "NIST SP 800-190 §4.4.3",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[
                self.evidence(
                    f"container.{src}.read_only_rootfs",
                    read_only,
                    ctx["inspect_cmd"],
                )
            ],
        )

    def _check_resource_limits(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        mem_set = ctx.get("memory_limit_set", False)
        cpu_set = ctx.get("cpu_limit_set", False)

        if mem_set and cpu_set:
            status = Status.PASS
        elif mem_set or cpu_set:
            status = Status.WARN
        else:
            status = Status.FAIL

        actual = f"memory_limit={'set' if mem_set else 'unset'}, cpu_limit={'set' if cpu_set else 'unset'}"

        return CheckResult(
            check_id="RD-CONT-005",
            title="Verify Redis container has memory and CPU resource limits configured",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="6.5",
            cis_id="draft-6.5",
            fedramp_control="SC-6",
            nist_800_53_controls=["SC-6", "SI-17"],
            description=(
                "Resource limits prevent a Redis container from consuming unbounded host "
                "CPU or memory, which could cause denial-of-service to co-located workloads."
            ),
            rationale=(
                "Without limits, a Redis memory spike (e.g. from a large dataset or leak) "
                "can exhaust host memory and cause OOM kills across unrelated workloads. "
                "CPU limits prevent noisy-neighbor impacts in shared environments."
            ),
            actual=actual,
            expected="both memory and CPU limits set",
            remediation=(
                "Set resources.limits.memory and resources.limits.cpu in the container spec "
                "(Kubernetes), or --memory and --cpus for docker run. "
                "Size limits based on expected Redis working set with headroom."
            ),
            references=[
                "CIS Docker Benchmark v1.6 §5.10",
                "CIS Kubernetes Benchmark v1.8 §5.2.3 (resource quotas)",
                "NIST SP 800-190 §4.5",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[
                self.evidence(
                    f"container.{src}.resource_limits",
                    {"memory_limit_set": mem_set, "cpu_limit_set": cpu_set},
                    ctx["inspect_cmd"],
                )
            ],
        )

    def _check_host_namespaces(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        host_network = ctx.get("host_network", False)
        host_pid = ctx.get("host_pid", False)
        host_ipc = ctx.get("host_ipc", False)

        violations = []
        if host_network:
            violations.append("hostNetwork")
        if host_pid:
            violations.append("hostPID")
        if host_ipc:
            violations.append("hostIPC")

        actual = (
            f"hostNetwork={host_network}, hostPID={host_pid}, hostIPC={host_ipc}"
            + (f" [VIOLATIONS: {violations}]" if violations else "")
        )

        return CheckResult(
            check_id="RD-CONT-006",
            title="Verify Redis container does not share host network, PID, or IPC namespaces",
            status=Status.FAIL if violations else Status.PASS,
            severity=Severity.HIGH,
            benchmark_control_id="6.6",
            cis_id="draft-6.6",
            fedramp_control="SC-4",
            nist_800_53_controls=["SC-4", "SC-7", "AC-6"],
            description=(
                "Sharing host namespaces collapses isolation boundaries between the Redis "
                "container and the host or other containers."
            ),
            rationale=(
                "hostNetwork exposes Redis to all host interfaces and removes network isolation. "
                "hostPID allows the container to inspect and signal host processes. "
                "hostIPC allows shared memory access across container boundaries. "
                "None of these are required by Redis in a correctly designed deployment."
            ),
            actual=actual,
            expected="hostNetwork=False, hostPID=False, hostIPC=False",
            remediation=(
                "Remove hostNetwork, hostPID, and hostIPC from the pod spec. "
                "If network performance is a concern, use a CNI plugin rather than hostNetwork."
            ),
            references=[
                "CIS Docker Benchmark v1.6 §5.14, §5.16, §5.17",
                "CIS Kubernetes Benchmark v1.8 §5.2.2, §5.2.3, §5.2.4",
                "NIST SP 800-190 §4.4.2",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[
                self.evidence(
                    f"container.{src}.namespaces",
                    {
                        "hostNetwork": host_network,
                        "hostPID": host_pid,
                        "hostIPC": host_ipc,
                    },
                    ctx["inspect_cmd"],
                )
            ],
        )

    # ------------------------------------------------------------------
    # Helpers for SKIP / ERROR states
    # ------------------------------------------------------------------

    def _all_skipped(self) -> list[CheckResult]:
        _CHECKS = [
            ("RD-CONT-001", "Verify Redis process runs as a non-root user"),
            ("RD-CONT-002", "Verify Redis container does not run in privileged mode"),
            ("RD-CONT-003", "Verify dangerous Linux capabilities are not granted to the Redis container"),
            ("RD-CONT-004", "Verify Redis container root filesystem is mounted read-only"),
            ("RD-CONT-005", "Verify Redis container has memory and CPU resource limits configured"),
            ("RD-CONT-006", "Verify Redis container does not share host network, PID, or IPC namespaces"),
        ]
        return [
            CheckResult(
                check_id=cid,
                title=title,
                status=Status.SKIP,
                severity=Severity.INFO,
                benchmark_control_id=f"6.{i + 1}",
                cis_id=f"draft-6.{i + 1}",
                fedramp_control=None,
                nist_800_53_controls=[],
                description="Container-level controls require docker or kubectl mode.",
                rationale="Container inspection is not available in direct/CLI mode.",
                actual="direct mode — container inspection not available",
                expected="run with --mode docker or --mode kubectl",
                remediation=(
                    "Re-run with --mode docker --container <name> or "
                    "--mode kubectl --pod <name> to assess container-level controls."
                ),
                references=[
                    "CIS Docker Benchmark",
                    "CIS Kubernetes Benchmark",
                ],
                category="Container",
                evidence_type="container-config",
                evidence=[],
            )
            for i, (cid, title) in enumerate(_CHECKS)
        ]

    def _all_error(self, mode: str) -> list[CheckResult]:
        container_ref = (
            self.runner.container if mode == "docker" else self.runner.pod
        ) or "<unknown>"
        _CHECKS = [
            ("RD-CONT-001", "Verify Redis process runs as a non-root user"),
            ("RD-CONT-002", "Verify Redis container does not run in privileged mode"),
            ("RD-CONT-003", "Verify dangerous Linux capabilities are not granted to the Redis container"),
            ("RD-CONT-004", "Verify Redis container root filesystem is mounted read-only"),
            ("RD-CONT-005", "Verify Redis container has memory and CPU resource limits configured"),
            ("RD-CONT-006", "Verify Redis container does not share host network, PID, or IPC namespaces"),
        ]
        inspect_cmd = (
            f"docker inspect {container_ref}"
            if mode == "docker"
            else f"kubectl get pod {container_ref} -o json"
        )
        return [
            CheckResult(
                check_id=cid,
                title=title,
                status=Status.ERROR,
                severity=Severity.HIGH,
                benchmark_control_id=f"6.{i + 1}",
                cis_id=f"draft-6.{i + 1}",
                fedramp_control=None,
                nist_800_53_controls=[],
                description="Container inspection failed; controls could not be assessed.",
                rationale="Evidence cannot be collected if the runtime inspection command fails.",
                actual=f"inspection failed for {container_ref}",
                expected="successful container inspect output",
                remediation=(
                    f"Verify the container/pod exists and the audit user has permission to run: "
                    f"{inspect_cmd}"
                ),
                references=[
                    "CIS Docker Benchmark",
                    "CIS Kubernetes Benchmark",
                ],
                category="Container",
                evidence_type="container-config",
                evidence=[self.evidence("container.inspect_error", f"failed: {inspect_cmd}", inspect_cmd)],
            )
            for i, (cid, title) in enumerate(_CHECKS)
        ]
