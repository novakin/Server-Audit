"""Read-only local Docker inventory with an explicit metadata allowlist."""

import ipaddress
import json
import re


DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]

# Project fields inside the CLI, so environment, labels, commands and health logs
# never enter the captured inspect output.
FIELDS = {
    "id": ".Id", "name": ".Name", "image": ".Config.Image", "image_id": ".Image",
    "created": ".Created", "status": ".State.Status", "running": ".State.Running",
    "started": ".State.StartedAt", "finished": ".State.FinishedAt",
    "exit_code": ".State.ExitCode", "oom_killed": ".State.OOMKilled",
    "restart_count": ".RestartCount", "user": ".Config.User",
    "privileged": ".HostConfig.Privileged", "readonly_rootfs": ".HostConfig.ReadonlyRootfs",
    "network_mode": ".HostConfig.NetworkMode", "pid_mode": ".HostConfig.PidMode",
    "ipc_mode": ".HostConfig.IpcMode", "userns_mode": ".HostConfig.UsernsMode",
    "cap_add": ".HostConfig.CapAdd", "cap_drop": ".HostConfig.CapDrop",
    "security_options": ".HostConfig.SecurityOpt", "devices": ".HostConfig.Devices",
    "restart_policy": ".HostConfig.RestartPolicy", "memory_bytes": ".HostConfig.Memory",
    "memory_swap_bytes": ".HostConfig.MemorySwap", "nano_cpus": ".HostConfig.NanoCpus",
    "cpu_quota": ".HostConfig.CpuQuota", "cpu_period": ".HostConfig.CpuPeriod",
    "cpuset": ".HostConfig.CpusetCpus", "pids_limit": ".HostConfig.PidsLimit",
    "published_ports": ".NetworkSettings.Ports", "configured_ports": ".HostConfig.PortBindings",
    "log_driver": ".HostConfig.LogConfig.Type",
}
INSPECT_FORMAT = '{' + ','.join(json.dumps(key) + ':{{json ' + expression + '}}' for key, expression in FIELDS.items())
INSPECT_FORMAT += ',"health":{{with index .State "Health"}}{{json .Status}}{{else}}null{{end}}'
INSPECT_FORMAT += ',"environment_variable_count":{{with index .Config "Env"}}{{len .}}{{else}}0{{end}}'
INSPECT_FORMAT += ',"mounts":[{{range $i,$m := .Mounts}}{{if $i}},{{end}}{"type":{{json $m.Type}},"source":{{json $m.Source}},"destination":{{json $m.Destination}},"writable":{{json $m.RW}}}{{end}}]'
INSPECT_FORMAT += ',"networks":[{{$first := true}}{{range $name,$n := .NetworkSettings.Networks}}{{if not $first}},{{end}}{{$first = false}}{"name":{{json $name}},"ipv4":{{json $n.IPAddress}},"ipv6":{{json $n.GlobalIPv6Address}}}{{end}}]}'


def findings_for(container):
    reasons = []
    if container.get("privileged"):
        reasons.append("privileged mode grants broad host access")
    for field in ("network_mode", "pid_mode", "ipc_mode", "userns_mode"):
        if container.get(field) == "host":
            reasons.append(field + " uses host namespace")
    user = container.get("user", "") or ""
    if user.split(":", 1)[0] in ("", "0", "root"):
        reasons.append("configured user is root/default; actual process identity and user-namespace mapping are unverified")
    if container.get("cap_add"):
        reasons.append("added Linux capabilities: " + ", ".join(container["cap_add"]))
    if container.get("devices"):
        reasons.append("host devices are passed through")
    if any("unconfined" in option for option in container.get("security_options") or []):
        reasons.append("an isolation profile is explicitly unconfined")
    for mount in container.get("mounts") or []:
        source = mount.get("source", "")
        if source.endswith("docker.sock"):
            reasons.append("Docker socket mounted; read-only bind does not make the Docker API read-only")
        elif mount.get("type") == "bind" and mount.get("writable") and (source == "/" or any(source == prefix or source.startswith(prefix + "/") for prefix in ("/etc", "/proc", "/sys", "/dev", "/root", "/run", "/var/run"))):
            reasons.append("writable sensitive host bind mount: " + source)
    for port, bindings in (container.get("published_ports") or {}).items():
        for binding in bindings or []:
            host = binding.get("HostIp", "")
            try:
                address = ipaddress.ip_address(host)
                loopback = address.is_loopback or bool(getattr(address, 'ipv4_mapped', None) and address.ipv4_mapped.is_loopback)
            except ValueError:
                loopback = False
            if not loopback:
                reasons.append(f"port {port} published on {host or '*'}:{binding.get('HostPort', '?')}; external reachability unverified")
    if container.get("health") == "unhealthy":
        reasons.append("health check reports unhealthy")
    if container.get("oom_killed"):
        reasons.append("last container state records an out-of-memory kill")
    if container.get("status") == "restarting":
        reasons.append("container is restarting")
    if container.get("status") == "exited" and container.get("exit_code"):
        reasons.append(f"container exited with code {container['exit_code']}")
    name = container.get("name") or container.get("id", "unknown")
    return [{"level": "REVIEW", "message": f"Docker {name}: {reason}."} for reason in reasons]


def collect(run):
    listing = run(DOCKER + ["ps", "--all", "--quiet", "--no-trunc"])
    if listing["status"] == "unavailable":
        return {"status": "skipped", "detail": "Docker audit skipped: Docker CLI not found in the audit PATH. No container inspection attempted; daemon presence is unverified."}, []
    if listing["status"] != "ok":
        return listing, []
    containers = []
    findings = []
    for identifier in listing.get("output", "").splitlines():
        if not re.fullmatch(r"[0-9a-f]{64}", identifier):
            return {"status": "error", "detail": "Docker returned an invalid container ID; inventory incomplete"}, findings
        result = run(DOCKER + ["inspect", "--type", "container", "--format", INSPECT_FORMAT, identifier])
        if result["status"] != "ok":
            containers.append({"id": identifier, "inspection_status": "error", "detail": result.get("detail", "Inspection failed")})
            findings.append({"level": "UNKNOWN", "message": f"Docker {identifier[:12]} inspection failed; container may have disappeared or access was denied."})
            continue
        try:
            container = json.loads(result["output"])
            if not isinstance(container, dict) or container.get("id") != identifier:
                raise ValueError("Unexpected container identity")
        except (ValueError, KeyError):
            containers.append({"id": identifier, "inspection_status": "error", "detail": "Invalid projected inspect output"})
            findings.append({"level": "UNKNOWN", "message": f"Docker {identifier[:12]} returned invalid inspection output."})
            continue
        # Keep only the allowlisted projection even if a CLI returns extra fields.
        container = {key: value for key, value in container.items() if key in FIELDS or key in {"health", "mounts", "networks", "environment_variable_count"}}
        container["inspection_status"] = "ok"
        containers.append(container)
        findings.extend(findings_for(container))
    return {"status": "ok", "containers": containers, "endpoint": DOCKER[2],
            "limitations": [
                "Local default Docker socket only; rootless daemons, remote contexts, Podman and Swarm service specifications are not covered.",
                "All containers, including stopped ones, are inspected. Listing and inspection are not an atomic snapshot.",
                "Published ports do not prove internet reachability; host/macvlan/ipvlan networking may expose services without port mappings.",
                "Configured users, capabilities and limits are configuration evidence, not measured process privileges or live resource usage. Zero/null limits may inherit daemon or parent-cgroup limits.",
                "No container exec, image pulls, container logs or vulnerability scans. Environment, commands, labels, health-check output and log-driver options are excluded.",
            ]}, findings
