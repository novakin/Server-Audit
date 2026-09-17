#!/usr/bin/env bash
# Destructive fixture preparation is allowed only on an explicitly disposable VM.
set -Eeuo pipefail

if [[ ${1:-} != --disposable-vm || $# != 2 || $EUID != 0 ]]; then
    echo 'Usage (disposable VM only): sudo bash tests/integration_lab.sh --disposable-vm /absolute/python' >&2
    exit 2
fi
python=$2
[[ $python == /* && -x $python ]] || { echo 'An absolute Python executable is required.' >&2; exit 2; }
[[ -f tests/test_live_integrations.py ]] || { echo 'Run from the repository root.' >&2; exit 2; }
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export LC_ALL=C
umask 077

lab=/opt/lab
results=/results
marker=/run/server-security-audit-integration-lab
keys=/root/.ssh/authorized_keys
image=server-audit-integration:local
nft_table=server_audit_integration
iptables_chain=AUDIT_INTEGRATION
sshd_pid=''
created_lab=0 created_results=0 created_marker=0 created_keys=0
created_ssh_dir=0 created_run_sshd=0 created_policy=0
created_image=0 created_web=0 created_stopped=0 created_nft=0 created_iptables=0

# The audit's Docker collector explicitly uses this local socket too.
docker_executable=$(type -P docker) || { echo 'The disposable VM must already have Docker installed.' >&2; exit 2; }
docker() { timeout 45 "$docker_executable" --host unix:///var/run/docker.sock "$@"; }
for path in "$lab" "$results" "$marker" "$keys"; do
    [[ ! -e $path && ! -L $path ]] || { echo "Refusing existing lab resource: $path" >&2; exit 2; }
done
docker info >/dev/null
[[ -z $(docker ps -aq) ]] || { echo 'Refusing a Docker daemon with existing containers.' >&2; exit 2; }
if docker image inspect "$image" >/dev/null 2>&1; then
    echo 'Refusing an existing fixture image.' >&2
    exit 2
fi

cleanup() {
    status=$?
    trap - EXIT INT TERM
    set +e
    cleanup_failed=0
    cleanup_command() {
        "$@" || { echo "Cleanup failed: $1" >&2; cleanup_failed=1; }
    }
    if [[ -n $sshd_pid ]]; then
        if kill -0 "$sshd_pid" 2>/dev/null; then
            kill -TERM "$sshd_pid"
            for ((attempt=0; attempt<20; attempt++)); do
                kill -0 "$sshd_pid" 2>/dev/null || break
                sleep 0.1
            done
            if kill -0 "$sshd_pid" 2>/dev/null; then
                cleanup_command kill -KILL "$sshd_pid"
            fi
        fi
        wait "$sshd_pid" 2>/dev/null
    fi
    ((created_web)) && cleanup_command docker rm -f audit-integration-web
    ((created_stopped)) && cleanup_command docker rm -f audit-integration-stopped
    ((created_image)) && cleanup_command docker image rm "$image"
    if ((created_iptables)); then
        cleanup_command timeout 10 iptables -w 5 -F "$iptables_chain"
        cleanup_command timeout 10 iptables -w 5 -X "$iptables_chain"
    fi
    ((created_nft)) && cleanup_command timeout 10 nft delete table inet "$nft_table"
    if ((status != 0 && created_results)); then
        for log in "$results/sshd.log" "$results/ssh-client.err"; do
            [[ ! -f $log ]] || tail -n 60 "$log" >&2
        done
    fi
    ((created_marker)) && cleanup_command rm -- "$marker"
    ((created_keys)) && cleanup_command rm -- "$keys"
    ((created_ssh_dir)) && cleanup_command rmdir /root/.ssh
    ((created_run_sshd)) && cleanup_command rmdir /run/sshd
    ((created_policy)) && cleanup_command rm -- /usr/sbin/policy-rc.d
    ((created_results)) && cleanup_command rm -rf -- "$results"
    ((created_lab)) && cleanup_command rm -rf -- "$lab"
    if ((cleanup_failed)); then
        ((status != 0)) || status=1
    else
        echo 'Lab cleanup completed.'
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Suppress package-triggered service starts without replacing existing policy.
if [[ ! -e /usr/sbin/policy-rc.d && ! -L /usr/sbin/policy-rc.d ]]; then
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
    chmod 755 /usr/sbin/policy-rc.d
    created_policy=1
fi
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=3 update
apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
    openssh-server openssh-client busybox-static iproute2 nftables iptables
if ((created_policy)); then
    rm /usr/sbin/policy-rc.d
    created_policy=0
fi
for tool in sshd ssh ssh-keygen busybox ss nft iptables iptables-save ip6tables-save; do
    command -v "$tool" >/dev/null || { echo "Missing fixture prerequisite: $tool" >&2; exit 1; }
done
busybox --list | grep -Fx httpd >/dev/null
busybox --list | grep -Fx wget >/dev/null
[[ -z $(ss -H -lnt '( sport = :22222 or sport = :18080 )') ]] || { echo 'Lab ports are already occupied.' >&2; exit 2; }
nft list ruleset >/dev/null
iptables-save >/dev/null
ip6tables-save >/dev/null
if nft list table inet "$nft_table" >/dev/null 2>&1 || iptables -w 5 -S "$iptables_chain" >/dev/null 2>&1; then
    echo 'Refusing existing fixture firewall resources.' >&2
    exit 2
fi

mkdir "$lab"; created_lab=1
mkdir "$results"; created_results=1
if [[ ! -d /root/.ssh ]]; then mkdir -m 700 /root/.ssh; created_ssh_dir=1; fi
if [[ ! -d /run/sshd ]]; then mkdir -m 755 /run/sshd; created_run_sshd=1; fi
ssh-keygen -q -t ed25519 -N '' -f "$lab/host_key"
ssh-keygen -q -t ed25519 -N '' -f "$lab/client_key"
cp "$lab/client_key.pub" "$keys"; created_keys=1
chmod 600 "$keys"
printf '[127.0.0.1]:22222 %s\n' "$(cat "$lab/host_key.pub")" > "$lab/known_hosts"
cat > "$lab/sshd_config" <<'CONFIG'
Port 22222
ListenAddress 127.0.0.1
HostKey /opt/lab/host_key
PidFile /opt/lab/sshd.pid
AuthorizedKeysFile /root/.ssh/authorized_keys
PermitRootLogin prohibit-password
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
AllowUsers root
AllowTcpForwarding no
UseDNS no
PrintMotd no
LogLevel VERBOSE
Match User root Address 127.0.0.1
    AllowTcpForwarding yes
CONFIG
sshd -t -f "$lab/sshd_config"
/usr/sbin/sshd -D -e -f "$lab/sshd_config" > "$results/sshd.log" 2>&1 &
sshd_pid=$!

wait_for() {
    description=$1
    shift
    deadline=$((SECONDS + 45))
    until "$@"; do
        if ((SECONDS >= deadline)); then echo "Readiness deadline exceeded: $description" >&2; return 1; fi
        sleep 0.5
    done
}
ssh_ready() {
    timeout 5 ssh -F /dev/null -p 22222 -i "$lab/client_key" \
        -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=2 \
        -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$lab/known_hosts" \
        root@127.0.0.1 'printf audit-live-ssh-ok' \
        > "$results/ssh-client.txt" 2> "$results/ssh-client.err"
}
wait_for 'SSH key login' ssh_ready

# Import a local, env-free rootfs. No mutable registry image or Dockerfile builder.
mkdir -p "$lab/rootfs/bin" "$lab/rootfs/www"
cp "$(command -v busybox)" "$lab/rootfs/bin/busybox"
chmod 755 "$lab/rootfs/bin/busybox"
ln -s busybox "$lab/rootfs/bin/sh"
printf 'audit-live-http-ok\n' > "$lab/rootfs/www/index.html"
chmod 755 "$lab/rootfs" "$lab/rootfs/bin" "$lab/rootfs/www"
chmod 644 "$lab/rootfs/www/index.html"
created_image=1
tar -C "$lab/rootfs" -cf - . | docker image import - "$image"
created_stopped=1
docker create --name audit-integration-stopped --user 1000:1000 --read-only \
    "$image" /bin/busybox true
created_web=1
docker run -d --name audit-integration-web --publish 127.0.0.1:18080:80 \
    --memory 64m --pids-limit 64 --env AUDIT_FIXTURE=PRIVATE_SENTINEL_LIVE \
    --label audit-fixture=PRIVATE_SENTINEL_LIVE --health-interval 1s --health-timeout 2s \
    --health-retries 10 \
    --health-cmd ': PRIVATE_SENTINEL_LIVE; /bin/busybox wget -q -O /dev/null http://127.0.0.1/' \
    "$image" /bin/busybox httpd -f -p 80 -h /www
web_ready() { [[ $(docker inspect --format '{{.State.Health.Status}}' audit-integration-web) == healthy ]]; }
wait_for 'Docker HTTP health check' web_ready

# Unhooked chains provide real evidence without changing packet filtering policy.
nft add table inet "$nft_table"; created_nft=1
nft add chain inet "$nft_table" evidence
nft add rule inet "$nft_table" evidence tcp dport 22222 counter comment '"audit-integration-ssh"'
iptables -w 5 -N "$iptables_chain"; created_iptables=1
iptables -w 5 -A "$iptables_chain" -p tcp --dport 18080 -m comment --comment audit-integration-docker -j RETURN

# Publish the misuse guard only after all fixtures are ready.
printf 'Disposable GitHub/explicit VM integration fixture\n' > "$marker"; created_marker=1
"$python" --version
docker version --format '{{.Server.Version}}'
ssh -V
nft --version
iptables --version
dpkg-query -W -f='${Package} ${Version}\n' openssh-server busybox-static
AUDIT_LIVE_INTEGRATION=1 PYTHONDONTWRITEBYTECODE=1 "$python" -m tests.live_ci
