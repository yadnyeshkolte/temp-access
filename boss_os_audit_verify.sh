#!/usr/bin/env bash
###############################################################################
# BOSS OS 11 (Debian 13) - Security Audit Finding Verification Script
#
# Purpose : Re-checks each bug-bounty / audit finding against the LIVE system
#           and reports whether the condition still exists (VULNERABLE),
#           has been fixed (NOT-PRESENT), could not be checked automatically
#           (MANUAL-GUI / MANUAL-PHYSICAL), or errored during the check
#           (CHECK-ERROR, e.g. missing tool / needs root).
#
# Usage   : sudo ./boss_os_audit_verify.sh          # full run (recommended)
#           ./boss_os_audit_verify.sh                # partial run, non-root
#           ./boss_os_audit_verify.sh > report.txt   # save report
#           ./boss_os_audit_verify.sh --csv > report.csv
#
# Notes   : - This script is READ-ONLY / non-destructive. It never modifies
#             system state, only inspects it.
#           - Findings whose original PoC required interactive GUI apps
#             (Files, Settings, Characters, Contacts, Clocks, etc.) or
#             physical access (USB boot, BIOS/UEFI menu, external live
#             media) CANNOT be verified from a shell and are reported as
#             MANUAL-GUI / MANUAL-PHYSICAL. Verify those by hand.
#           - Some checks need root to be meaningful (e.g. /etc/shadow perms,
#             auditctl, dmesg). Run with sudo for a complete pass.
###############################################################################

set -uo pipefail

# ---------- output handling --------------------------------------------------
CSV=0
[[ "${1:-}" == "--csv" ]] && CSV=1

RESULTS=()   # collects "ID|TITLE|STATUS|DETAIL" rows

record() {
    local id="$1" title="$2" status="$3" detail="$4"
    RESULTS+=("${id}|${title}|${status}|${detail}")
}

# status helpers
VULN="VULNERABLE"
OK="NOT-PRESENT"
GUI="MANUAL-GUI"
PHY="MANUAL-PHYSICAL"
ERR="CHECK-ERROR"

need_root_note="(needs root for a definitive result)"

is_root() { [[ $EUID -eq 0 ]]; }

###############################################################################
# Individual checks
###############################################################################

chk_S00320821() { # GRUB password not configured
    if grep -q '^GRUB_PASSWORD' /etc/default/grub 2>/dev/null || \
       grep -qi 'password' /etc/grub.d/40_custom 2>/dev/null; then
        record S00320821 "GRUB Password Not Configured" "$OK" "GRUB password directive found"
    else
        record S00320821 "GRUB Password Not Configured" "$VULN" "No GRUB_PASSWORD entry in /etc/default/grub"
    fi
}

chk_S01300735() { # fapolicyd config errors / db overflow
    if ! command -v fapolicyd >/dev/null 2>&1 && [[ ! -f /etc/fapolicyd/fapolicyd.conf ]]; then
        record S01300735 "fapolicyd Config Errors / DB Overflow" "$ERR" "fapolicyd not installed"
        return
    fi
    local integrity dbsize status
    integrity=$(grep -E '^\s*integrity' /etc/fapolicyd/fapolicyd.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    dbsize=$(stat -c%s /var/lib/fapolicyd/data.mdb 2>/dev/null || echo 0)
    status=$(systemctl is-active fapolicyd 2>/dev/null)
    if [[ "$integrity" == "none" ]] || [[ "$status" != "active" ]]; then
        record S01300735 "fapolicyd Config Errors / DB Overflow" "$VULN" "integrity=${integrity:-unknown}, service=${status:-unknown}, db_bytes=${dbsize}"
    else
        record S01300735 "fapolicyd Config Errors / DB Overflow" "$OK" "integrity=${integrity}, service=${status}, db_bytes=${dbsize}"
    fi
}

chk_W00160453() { # mod-pkg-rem re-creates chmod -x /dev/shm cron
    local f="/usr/client/mod-pkg-rem"
    if [[ -f "$f" ]] && grep -q 'chmod -x.*shm' "$f" 2>/dev/null; then
        record W00160453 "mod-pkg-rem Flawed /dev/shm Hardening" "$VULN" "cron entry re-introduced in $f"
    elif [[ -f "$f" ]]; then
        record W00160453 "mod-pkg-rem Flawed /dev/shm Hardening" "$OK" "no chmod -x /dev/shm cron line found in $f"
    else
        record W00160453 "mod-pkg-rem Flawed /dev/shm Hardening" "$ERR" "$f not found"
    fi
}

chk_S00430193() { # xdg-user-dirs systemd user service missing
    if systemctl --user status xdg-user-dirs.service >/dev/null 2>&1; then
        record S00430193 "Missing xdg-user-dirs systemd User Service" "$OK" "unit found"
    else
        record S00430193 "Missing xdg-user-dirs systemd User Service" "$VULN" "unit not found (run as the target user for accuracy)"
    fi
}

chk_S00540062() { # exim4 SUID
    local f="/usr/sbin/exim4"
    if [[ -u "$f" ]] 2>/dev/null; then
        record S00540062 "exim4 Insecure SUID Bit" "$VULN" "$(ls -la "$f" 2>/dev/null)"
    elif [[ -e "$f" ]]; then
        record S00540062 "exim4 Insecure SUID Bit" "$OK" "$(ls -la "$f" 2>/dev/null)"
    else
        record S00540062 "exim4 Insecure SUID Bit" "$ERR" "exim4 not installed"
    fi
}

chk_W00440269() { # os-prober enabled
    local prober_disabled pkg script
    prober_disabled=$(grep -i '^GRUB_DISABLE_OS_PROBER' /etc/default/grub 2>/dev/null)
    pkg=$(dpkg -l os-prober 2>/dev/null | grep -c '^ii')
    if [[ "$prober_disabled" == *"false"* ]] || { [[ -z "$prober_disabled" ]] && [[ "$pkg" -gt 0 ]]; }; then
        record W00440269 "GRUB os-prober Enabled" "$VULN" "GRUB_DISABLE_OS_PROBER=${prober_disabled:-unset}, os-prober installed=${pkg}"
    else
        record W00440269 "GRUB os-prober Enabled" "$OK" "os-prober disabled or not installed"
    fi
}

chk_W03250362() { # sudoers.d permissions
    local perm
    perm=$(stat -c '%a' /etc/sudoers.d 2>/dev/null)
    if [[ -z "$perm" ]]; then
        record W03250362 "sudoers.d Incorrect Permissions" "$ERR" "cannot stat /etc/sudoers.d"
    elif [[ "$perm" == "750" || "$perm" == "700" ]]; then
        record W03250362 "sudoers.d Incorrect Permissions" "$OK" "perm=$perm"
    else
        record W03250362 "sudoers.d Incorrect Permissions" "$VULN" "perm=$perm (expected 750/700)"
    fi
}

chk_S00470744() { # SSLv3 cipher suites present
    local sslv3 minproto cryptopol
    sslv3=$(openssl ciphers -v 'ALL:COMPLEMENTOFALL' 2>/dev/null | grep -c 'SSLv3')
    minproto=$(grep -E 'MinProtocol|CipherString' /etc/ssl/openssl.cnf 2>/dev/null)
    cryptopol=$([[ -d /etc/crypto-policies ]] && echo present || echo absent)
    if [[ "$sslv3" -gt 0 || -z "$minproto" ]]; then
        record S00470744 "SSLv3 Ciphers Enabled / No MinProtocol" "$VULN" "sslv3_ciphers=$sslv3, MinProtocol/CipherString_set=$( [[ -n "$minproto" ]] && echo yes || echo no ), crypto-policies=$cryptopol"
    else
        record S00470744 "SSLv3 Ciphers Enabled / No MinProtocol" "$OK" "MinProtocol/CipherString enforced"
    fi
}

chk_S01170630() { # root shell nologin
    local shell
    shell=$(getent passwd root 2>/dev/null | cut -d: -f7)
    if [[ "$shell" == *nologin* ]]; then
        record S01170630 "Root Shell Set to nologin" "$VULN" "root shell=$shell"
    else
        record S01170630 "Root Shell Set to nologin" "$OK" "root shell=$shell"
    fi
}

chk_S00610800() { # AppArmor confinement for IBus
    if ! command -v aa-status >/dev/null 2>&1; then
        record S00610800 "Missing AppArmor Confinement for IBus" "$ERR" "apparmor-utils not installed / cannot query"
        return
    fi
    local ibus_confined
    ibus_confined=$(aa-status 2>/dev/null | grep -ci 'ibus')
    if [[ "$ibus_confined" -gt 0 ]]; then
        record S00610800 "Missing AppArmor Confinement for IBus" "$OK" "an AppArmor profile referencing ibus is loaded"
    else
        record S00610800 "Missing AppArmor Confinement for IBus" "$VULN" "no AppArmor profile for IBus found (processes run unconfined)"
    fi
}

chk_secureboot_generic() { # shared by S02480701 / S00280747 / W00300414 / S02760696
    if ! command -v mokutil >/dev/null 2>&1; then
        for id in S02480701 S00280747 W00300414 S02760696; do
            record "$id" "UEFI Secure Boot Disabled / Setup Mode" "$ERR" "mokutil not installed"
        done
        return
    fi
    local out status
    out=$(mokutil --sb-state 2>&1)
    if echo "$out" | grep -qi 'SecureBoot enabled'; then
        status="$OK"
    else
        status="$VULN"
    fi
    for id in S02480701 S00280747 W00300414 S02760696; do
        record "$id" "UEFI Secure Boot Disabled / Setup Mode" "$status" "$out"
    done
}

chk_S00300753() { # firewall guard log dir permissions
    local d="/var/log/client"
    if [[ ! -d "$d" ]]; then
        record S00300753 "Firewall Guard Log Dir Inaccessible" "$ERR" "$d does not exist"
        return
    fi
    local perm
    perm=$(stat -c '%a' "$d")
    if (( (10#$perm) & 0111 )); then
        record S00300753 "Firewall Guard Log Dir Inaccessible" "$OK" "dir has execute bit, perm=$perm"
    else
        record S00300753 "Firewall Guard Log Dir Inaccessible" "$VULN" "dir lacks execute bit, perm=$perm"
    fi
}

chk_W03250365() { # proc mounted without hidepid
    local m
    m=$(grep -E '^proc ' /proc/mounts 2>/dev/null)
    if echo "$m" | grep -q 'hidepid='; then
        record W03250365 "proc Mounted Without hidepid" "$OK" "$m"
    else
        record W03250365 "proc Mounted Without hidepid" "$VULN" "$m"
    fi
}

chk_S00370746() { # Lynis audit
    if ! command -v lynis >/dev/null 2>&1; then
        record S00370746 "Lynis Compatibility / Hardening Gaps" "$ERR" "lynis not installed - run 'lynis audit system' manually"
        return
    fi
    record S00370746 "Lynis Compatibility / Hardening Gaps" "$ERR" "run 'sudo lynis audit system' interactively and review warnings/suggestions (not auto-parsed here)"
}

chk_S00980496() { # kernel debug/logging protection
    local dmesg_denied strace_present
    if is_root; then
        record S00980496 "Kernel Debug/Log Protection" "$ERR" "run as non-root user to validate dmesg restriction"
        return
    fi
    dmesg 2>&1 | grep -qi 'permission denied' && dmesg_denied=1 || dmesg_denied=0
    command -v strace >/dev/null 2>&1 && strace_present=1 || strace_present=0
    if [[ "$dmesg_denied" -eq 1 ]]; then
        record S00980496 "Kernel Debug/Log Protection" "$OK" "dmesg access denied to unprivileged user; strace_installed=$strace_present"
    else
        record S00980496 "Kernel Debug/Log Protection" "$VULN" "dmesg readable by unprivileged user; strace_installed=$strace_present"
    fi
}

chk_S02340861() { # /etc/shadow permissions
    local perm
    perm=$(stat -c '%a' /etc/shadow 2>/dev/null)
    if [[ -z "$perm" ]]; then
        record S02340861 "/etc/shadow Improper Permissions" "$ERR" "need root to stat /etc/shadow"
        return
    fi
    if [[ "$perm" == "640" || "$perm" == "600" || "$perm" == "0" ]]; then
        record S02340861 "/etc/shadow Improper Permissions" "$OK" "perm=$perm"
    else
        record S02340861 "/etc/shadow Improper Permissions" "$VULN" "perm=$perm"
    fi
    # note: original finding calls 640 itself a violation vs CIS 0/600 recommendation
    if [[ "$perm" == "640" ]]; then
        record S02340861 "/etc/shadow Improper Permissions (CIS 000)" "$VULN" "perm=640 grants group-read; CIS recommends 000/600"
    fi
}

chk_W03250369() { # promiscuous mode
    local promisc
    promisc=$(ip link show 2>/dev/null | grep -c 'PROMISC')
    if [[ "$promisc" -gt 0 ]]; then
        record W03250369 "Network Interface in Promiscuous Mode" "$VULN" "$(ip link show | grep PROMISC)"
    else
        record W03250369 "Network Interface in Promiscuous Mode" "$OK" "no PROMISC flag set"
    fi
}

chk_S00660743() { # audit disabled / auditd missing
    local audit_enabled auditctl_present
    audit_enabled=$(dmesg 2>/dev/null | grep -o 'audit_enabled=[0-9]' | tail -1)
    command -v auditctl >/dev/null 2>&1 && auditctl_present=1 || auditctl_present=0
    if [[ "$audit_enabled" == "audit_enabled=0" || "$auditctl_present" -eq 0 ]]; then
        record S00660743 "Kernel Audit Disabled / auditd Missing" "$VULN" "${audit_enabled:-unknown (need root/dmesg)}, auditctl_installed=$auditctl_present"
    else
        record S00660743 "Kernel Audit Disabled / auditd Missing" "$OK" "$audit_enabled, auditctl_installed=$auditctl_present"
    fi
}

chk_S00300755() { # empty firewall config
    local nft_present ipt_present nft_active
    command -v nft >/dev/null 2>&1 && nft_present=1 || nft_present=0
    command -v iptables >/dev/null 2>&1 && ipt_present=1 || ipt_present=0
    nft_active=$(systemctl is-active nftables 2>/dev/null)
    if [[ "$nft_present" -eq 0 && "$ipt_present" -eq 0 ]] || [[ "$nft_active" != "active" ]]; then
        record S00300755 "Empty Firewall Configuration" "$VULN" "nft=$nft_present iptables=$ipt_present nftables_service=${nft_active:-inactive}"
    else
        record S00300755 "Empty Firewall Configuration" "$OK" "nft=$nft_present iptables=$ipt_present nftables_service=$nft_active"
    fi
}

chk_W00310044() { # fapolicyd extension-based bypass
    if ! command -v fapolicyd >/dev/null 2>&1; then
        record W00310044 "fapolicyd Trusts File Extensions" "$ERR" "fapolicyd not installed"
        return
    fi
    local tmp="/tmp/.fapolicyd_ext_test_$$"
    echo -e '#!/bin/sh\necho fapolicyd_bypass_test' > "${tmp}.sh"
    chmod +x "${tmp}.sh"
    cp "${tmp}.sh" "${tmp}.txt"
    chmod +x "${tmp}.txt"
    local sh_out txt_out
    sh_out=$("${tmp}.sh" 2>&1); sh_rc=$?
    txt_out=$("${tmp}.txt" 2>&1); txt_rc=$?
    rm -f "${tmp}.sh" "${tmp}.txt"
    if [[ $sh_rc -ne 0 && $txt_rc -eq 0 ]]; then
        record W00310044 "fapolicyd Trusts File Extensions" "$VULN" ".sh blocked but .txt copy executed successfully"
    else
        record W00310044 "fapolicyd Trusts File Extensions" "$OK" "sh_rc=$sh_rc txt_rc=$txt_rc (extension bypass not reproduced)"
    fi
}

chk_auditctl_norules() { # shared by many "no audit rules loaded" duplicates
    local ids=(W03250370 W01220455 W01220456 S00280764 S00830250 W01970401 S00820750 S01170770)
    if ! command -v auditctl >/dev/null 2>&1; then
        for id in "${ids[@]}"; do record "$id" "auditd Running With Zero Rules Loaded" "$ERR" "auditctl not installed"; done
        return
    fi
    local rules status
    rules=$(auditctl -l 2>&1)
    status=$(systemctl is-active auditd 2>/dev/null)
    local verdict
    if [[ "$rules" == *"No rules"* ]]; then verdict="$VULN"; else verdict="$OK"; fi
    for id in "${ids[@]}"; do
        record "$id" "auditd Running With Zero Rules Loaded" "$verdict" "auditd=${status:-unknown}, auditctl -l => ${rules}"
    done
}

chk_W01780371() { # sudoers unknown defaults warning
    local out
    out=$(sudo -V 2>&1 | grep -i 'unknown defaults')
    if [[ -n "$out" ]]; then
        record W01780371 "Invalid sudoers Defaults Entry" "$VULN" "$out"
    else
        record W01780371 "Invalid sudoers Defaults Entry" "$OK" "no 'unknown defaults' warning from sudo -V"
    fi
}

chk_W03250374() { # root quarantine dir with privileged scripts
    local d1="/root/quarantineb" d2="/root/quarantine"
    local found=""
    for d in "$d1" "$d2"; do
        [[ -d "$d" ]] && found="$found $(ls -la "$d" 2>/dev/null | tr '\n' ';')"
    done
    if [[ -n "$found" ]]; then
        record W03250374 "Root Quarantine Dir Has Privileged Script Copies" "$VULN" "$found"
    else
        record W03250374 "Root Quarantine Dir Has Privileged Script Copies" "$OK" "no quarantine directory with script copies found"
    fi
}

chk_W00300388() { # apt [trusted=yes] repos
    local hits
    hits=$(grep -rEl '\[trusted=yes\]|trusted=yes' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null)
    if [[ -n "$hits" ]]; then
        record W00300388 "APT [trusted=yes] Bypasses Signature Check" "$VULN" "$hits"
    else
        record W00300388 "APT [trusted=yes] Bypasses Signature Check" "$OK" "no trusted=yes entries found"
    fi
}

chk_S02770143() { # docker privileged containers
    if ! command -v docker >/dev/null 2>&1; then
        record S02770143 "Container Running With Excessive Privileges" "$OK" "docker not installed"
        return
    fi
    local priv
    priv=$(docker ps -q 2>/dev/null | xargs -r -I{} docker inspect --format '{{.Id}}: Privileged={{.HostConfig.Privileged}}' {} 2>/dev/null | grep -c 'Privileged=true')
    if [[ "$priv" -gt 0 ]]; then
        record S02770143 "Container Running With Excessive Privileges" "$VULN" "$priv privileged container(s) running"
    else
        record S02770143 "Container Running With Excessive Privileges" "$OK" "no privileged containers running"
    fi
}

chk_S01360640() { # ntfs-3g SUID
    local f="/usr/bin/ntfs-3g"
    if [[ -u "$f" ]] 2>/dev/null; then
        record S01360640 "ntfs-3g SUID Root" "$VULN" "$(ls -la "$f")"
    elif [[ -e "$f" ]]; then
        record S01360640 "ntfs-3g SUID Root" "$OK" "$(ls -la "$f")"
    else
        record S01360640 "ntfs-3g SUID Root" "$ERR" "ntfs-3g not installed"
    fi
}

chk_W03250390() { # ntfs-3g CVE-2022-40284 version check
    local ver
    ver=$(dpkg -s ntfs-3g 2>/dev/null | awk -F': ' '/^Version/{print $2}')
    if [[ -z "$ver" ]]; then
        record W03250390 "ntfs-3g CVE-2022-40284 (Vulnerable Version + SUID)" "$ERR" "ntfs-3g not installed"
        return
    fi
    if [[ "$ver" == "2022.10.3"* ]]; then
        record W03250390 "ntfs-3g CVE-2022-40284 (Vulnerable Version + SUID)" "$VULN" "installed version $ver matches CVE-affected 2022.10.3 - verify patch level for your distro/CVE tracker"
    else
        record W03250390 "ntfs-3g CVE-2022-40284 (Vulnerable Version + SUID)" "$OK" "installed version $ver (not the flagged 2022.10.3; confirm against current CVE feed)"
    fi
}

chk_S01300757() { # bossnet-chk.sh missing
    local f="/usr/bin/bossnet-chk.sh" wrapper="/usr/bin/boss-sec-wrapper.sh"
    local wrapper_commented="n/a"
    [[ -f "$wrapper" ]] && grep -q '#.*bossnet-chk.sh' "$wrapper" && wrapper_commented="yes"
    if [[ ! -f "$f" ]]; then
        record S01300757 "bossnet-chk.sh Missing" "$VULN" "$f absent; wrapper reference commented=$wrapper_commented"
    else
        record S01300757 "bossnet-chk.sh Missing" "$OK" "$f present"
    fi
}

chk_S00560476() { # tee deleted by boss-custominit
    local f="/usr/bin/tee" script="/usr/client/boss-custominit"
    local script_has_rm="no"
    [[ -f "$script" ]] && grep -q 'rm -rf /usr/bin/tee' "$script" && script_has_rm="yes"
    if [[ ! -e "$f" ]]; then
        record S00560476 "Destructive Deletion of /usr/bin/tee" "$VULN" "/usr/bin/tee missing; init script contains rm=$script_has_rm"
    else
        record S00560476 "Destructive Deletion of /usr/bin/tee" "$OK" "/usr/bin/tee present; init script contains rm=$script_has_rm"
    fi
}

chk_W03250380() { # unknown firewall-guard.sh
    local f="/usr/bin/firewall-guard.sh"
    if [[ ! -f "$f" ]]; then
        record W03250380 "Unpackaged firewall-guard.sh in /usr/bin" "$OK" "file not present"
        return
    fi
    local owner
    owner=$(dpkg -S "$f" 2>&1)
    if [[ "$owner" == *"no path found"* ]]; then
        record W03250380 "Unpackaged firewall-guard.sh in /usr/bin" "$VULN" "$f exists, owned by no package"
    else
        record W03250380 "Unpackaged firewall-guard.sh in /usr/bin" "$OK" "$owner"
    fi
}

chk_W00400299() { # FIPS mode
    local fips cmdline
    fips=$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)
    cmdline=$(grep -o 'fips=1' /proc/cmdline 2>/dev/null)
    if [[ "$fips" == "1" ]]; then
        record W00400299 "FIPS 140 Mode Not Enabled" "$OK" "fips_enabled=1"
    else
        record W00400299 "FIPS 140 Mode Not Enabled" "$VULN" "fips_enabled=${fips:-0/unreadable}, fips=1 kernel param present=$( [[ -n "$cmdline" ]] && echo yes || echo no )"
    fi
}

chk_W00370381() { # security packages installed under tmpfs
    local files
    files=$( { dpkg -L boss-secure-update 2>/dev/null; dpkg -L bossapparmor 2>/dev/null; } | grep '^/tmp/' )
    if [[ -n "$files" ]]; then
        record W00370381 "Security Packages Install to tmpfs" "$VULN" "$(echo "$files" | tr '\n' ';')"
    else
        record W00370381 "Security Packages Install to tmpfs" "$OK" "no package payload files under /tmp (packages may not be installed, or already fixed)"
    fi
}

chk_W03290454() { # fapolicyd missing default deny
    local f="/etc/fapolicyd/fapolicyd.conf"
    if [[ ! -f "$f" ]]; then
        record W03290454 "fapolicyd Missing Default-Deny Rule" "$ERR" "fapolicyd not installed"
        return
    fi
    local permissive
    permissive=$(grep -E '^\s*permissive' "$f" | awk -F= '{print $2}' | tr -d ' ')
    local last_rule
    last_rule=$(tail -n1 /etc/fapolicyd/rules.d/*.rules 2>/dev/null | grep -c 'deny_audit perm=any all : all')
    if [[ "$last_rule" -eq 0 ]]; then
        record W03290454 "fapolicyd Missing Default-Deny Rule" "$VULN" "permissive=${permissive:-0}; no terminating deny-all rule found in rules.d"
    else
        record W03290454 "fapolicyd Missing Default-Deny Rule" "$OK" "terminating deny-all rule present"
    fi
}

chk_tls_weak() { # W00710340 / W00440270 shared: weak TLS/SSL ciphers
    local weak
    weak=$(openssl ciphers -v 'ALL:COMPLEMENTOFDEFAULT' 2>/dev/null | grep -Ec 'SSLv3|TLSv1\.0|RC4|DES|MD5')
    local verdict; [[ "$weak" -gt 0 ]] && verdict="$VULN" || verdict="$OK"
    record W00710340 "Weak Default TLS/Cipher Config (TLS1.0/1.1, weak ciphers)" "$verdict" "weak_cipher_count=$weak"
    record W00440270 "Deprecated SSL/TLS Protocols Enabled" "$verdict" "weak_cipher_count=$weak"
}

chk_kernel_cve() { # generic: report kernel version for manual CVE cross-check
    local ids_titles=(
        "W00710389|IPv4 LSRR/SSRR Missing Capability Check (CVE-2026-53249, needs verification)"
        "W00710382|TIPC setsockopt Divide-by-Zero (CVE-2026-43411, needs verification)"
        "W00710392|Bonding Driver UAF in Broadcast TX (CVE-2026-31419, needs verification)"
        "W00710469|erofs LZ4 Decompression OOB Read (CVE-2026-45999, needs verification)"
        "W00710472|GFS2 fiemap Recursive Glock Deadlock (CVE-2026-43262, needs verification)"
        "W00710399|RDS TCP NULL Pointer Deref (CVE-2026-43226, needs verification)"
        "W00710485|DirtyClone Page-Cache LPE (CVE-2026-43503, needs verification)"
        "S01570863|algif_aead Local Privilege Escalation (needs CVE verification)"
    )
    local kver; kver=$(uname -r)
    for entry in "${ids_titles[@]}"; do
        local id="${entry%%|*}" title="${entry#*|}"
        record "$id" "$title" "$ERR" "running kernel=$kver; cross-check this exact build against the CVE fix commit/version manually - these PoCs in the source data include screenshots flagged 'fake' by evaluators, treat with suspicion"
    done
}

chk_W00130515() { # BPF JIT hardening off
    local v
    v=$(cat /proc/sys/net/core/bpf_jit_harden 2>/dev/null)
    if [[ "$v" == "0" ]]; then
        record W00130515 "BPF JIT Hardening Off" "$VULN" "bpf_jit_harden=0"
    elif [[ -n "$v" ]]; then
        record W00130515 "BPF JIT Hardening Off" "$OK" "bpf_jit_harden=$v"
    else
        record W00130515 "BPF JIT Hardening Off" "$ERR" "sysctl not readable"
    fi
}

chk_S00280760() { # tmpfs no size limit
    local out
    out=$(grep -E '\s(tmpfs)\s' /etc/fstab 2>/dev/null | grep -E '/tmp|/var/tmp|/dev/shm')
    if [[ -z "$out" ]]; then
        record S00280760 "tmpfs Mounts Without size= Limit" "$ERR" "no matching tmpfs lines found in /etc/fstab (may be mounted elsewhere, e.g. systemd defaults)"
        return
    fi
    if echo "$out" | grep -q 'size='; then
        record S00280760 "tmpfs Mounts Without size= Limit" "$OK" "$out"
    else
        record S00280760 "tmpfs Mounts Without size= Limit" "$VULN" "$out"
    fi
}

chk_W00440384_S00280763() { # sudo excessive privileges for current user
    local out
    out=$(sudo -l 2>&1)
    local risky
    risky=$(echo "$out" | grep -Ec 'ALL\s*:\s*ALL|/bin/bash|/bin/sh|/usr/bin/vim|/usr/bin/systemctl|NOPASSWD:\s*ALL')
    local verdict; [[ "$risky" -gt 0 ]] && verdict="$VULN" || verdict="$OK"
    record W00440384 "Improper Sudo Privilege Configuration" "$verdict" "sudo -l risky_line_count=$risky"
    record S00280763 "Sudoers ALL Access / Denylist Instead of Allowlist" "$verdict" "sudo -l risky_line_count=$risky"
}

chk_W02720391() { # NTP inactive breaking apt signature validation
    local ntp
    ntp=$(timedatectl status 2>/dev/null | grep -i 'System clock synchronized' | grep -c 'yes')
    if [[ "$ntp" -eq 0 ]]; then
        record W02720391 "NTP Inactive Breaking APT Signature Validation" "$VULN" "$(timedatectl status 2>/dev/null | grep -i synchronized)"
    else
        record W02720391 "NTP Inactive Breaking APT Signature Validation" "$OK" "clock synchronized"
    fi
}

chk_S01640841() { # logrotate insecure config
    local missingok nocreate compress
    missingok=$(grep -rl 'missingok' /etc/logrotate.conf /etc/logrotate.d/ 2>/dev/null | wc -l)
    nocreate=$(grep -rl 'nocreate' /etc/logrotate.conf /etc/logrotate.d/ 2>/dev/null | wc -l)
    compress=$(grep -c '^compress' /etc/logrotate.conf 2>/dev/null)
    if [[ "$missingok" -gt 0 || "$nocreate" -gt 0 || "$compress" -eq 0 ]]; then
        record S01640841 "Insecure Logrotate Config (missingok/nocreate/no compress)" "$VULN" "missingok_files=$missingok nocreate_files=$nocreate compress_enabled=$([[ "$compress" -gt 0 ]] && echo yes || echo no)"
    else
        record S01640841 "Insecure Logrotate Config (missingok/nocreate/no compress)" "$OK" "no risky directives found"
    fi
}

chk_W00440476() { # group-writable systemd unit
    local f="/etc/systemd/system/boss-secure.service"
    if [[ ! -f "$f" ]]; then
        record W00440476 "Group-Writable boss-secure.service Runs as Root" "$ERR" "$f not found"
        return
    fi
    local perm rootgrp
    perm=$(stat -c '%a' "$f")
    rootgrp=$(getent group root 2>/dev/null)
    if (( (10#$perm) & 020 )); then
        record W00440476 "Group-Writable boss-secure.service Runs as Root" "$VULN" "perm=$perm, group root membership: $rootgrp"
    else
        record W00440476 "Group-Writable boss-secure.service Runs as Root" "$OK" "perm=$perm"
    fi
}

chk_S00300822_S01620368() { # VFIO world-writable
    local f="/dev/vfio/vfio"
    if [[ ! -e "$f" ]]; then
        record S00300822 "VFIO Control Device World-Writable" "$ERR" "$f does not exist (module not loaded)"
        record S01620368 "VFIO Control Device World-Writable (dup)" "$ERR" "$f does not exist (module not loaded)"
        return
    fi
    local perm
    perm=$(stat -c '%a' "$f")
    if [[ "$perm" == "666" ]]; then
        record S00300822 "VFIO Control Device World-Writable" "$VULN" "perm=$perm"
        record S01620368 "VFIO Control Device World-Writable (dup)" "$VULN" "perm=$perm"
    else
        record S00300822 "VFIO Control Device World-Writable" "$OK" "perm=$perm"
        record S01620368 "VFIO Control Device World-Writable (dup)" "$OK" "perm=$perm"
    fi
}

chk_S01300774() { # kernel lockdown mode not applied
    local lockdown
    lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null)
    if [[ "$lockdown" == *'[none]'* ]]; then
        record S01300774 "Kernel Lockdown Mode Not Applied" "$VULN" "$lockdown"
    elif [[ -n "$lockdown" ]]; then
        record S01300774 "Kernel Lockdown Mode Not Applied" "$OK" "$lockdown"
    else
        record S01300774 "Kernel Lockdown Mode Not Applied" "$ERR" "lockdown interface not readable (need root, or LSM not built)"
    fi
}

chk_S00570801() { # orphaned symlinks pico/rnano/chronyd
    local broken
    broken=$(find /etc /usr/bin -maxdepth 2 -xtype l 2>/dev/null | grep -E 'pico|rnano|chronyd')
    if [[ -n "$broken" ]]; then
        record S00570801 "Orphaned Symlinks (pico/rnano/chronyd)" "$VULN" "$(echo "$broken" | tr '\n' ';')"
    else
        record S00570801 "Orphaned Symlinks (pico/rnano/chronyd)" "$OK" "no broken symlinks matching pico/rnano/chronyd"
    fi
}

chk_S00460335() { # frequent polling interval wrapper
    local f="/usr/bin/boss-sec-wrapper.sh"
    if [[ ! -f "$f" ]]; then
        record S00460335 "Frequent 10s Polling in Security Wrapper" "$ERR" "$f not found"
        return
    fi
    if grep -Eq 'sleep 10\b' "$f"; then
        record S00460335 "Frequent 10s Polling in Security Wrapper" "$VULN" "fixed 10s sleep interval confirmed in $f"
    else
        record S00460335 "Frequent 10s Polling in Security Wrapper" "$OK" "no fixed 10s sleep interval found"
    fi
}

chk_W01210329_W00120422() { # insecure tmp install path for security packages
    local files
    files=$( { dpkg -L boss-secure-update 2>/dev/null; dpkg -L bossapparmor 2>/dev/null; } | grep '^/tmp/' )
    local verdict; [[ -n "$files" ]] && verdict="$VULN" || verdict="$OK"
    record W01210329 "Insecure /tmp Install Path (packages)" "$verdict" "${files:-no /tmp payload files found}"
    record W00120422 "postinst Race via /tmp Staging" "$verdict" "${files:-no /tmp payload files found}"
}

chk_N00220182() { # root nologin bypassable via su -s / run0 / systemd-run
    local shell
    shell=$(getent passwd root | cut -d: -f7)
    if [[ "$shell" == *nologin* ]]; then
        record N00220182 "Root nologin Bypassable via su -s/run0/systemd-run" "$VULN" "root shell=$shell; confirm bypass manually with 'su -s /bin/bash -' or 'run0' (not auto-executed by this script for safety)"
    else
        record N00220182 "Root nologin Bypassable via su -s/run0/systemd-run" "$OK" "root already has an interactive shell: $shell"
    fi
}

chk_N00120152() { # session enumeration
    local out
    out=$(loginctl list-sessions 2>&1)
    record N00120152 "Local User Session Enumeration Possible" "$VULN" "any local user can run 'loginctl list-sessions' / 'who' - by design on most Linux systems: $(echo "$out" | head -3 | tr '\n' ';')"
}

chk_S00560374() { # util-linux CVE / PAM smartcard
    local ver
    ver=$(dpkg -s util-linux 2>/dev/null | awk -F': ' '/^Version/{print $2}')
    if [[ -z "$ver" ]]; then
        record S00560374 "util-linux CVE-2026-3184 / PAM Smartcard Bypass" "$ERR" "could not determine util-linux version"
        return
    fi
    record S00560374 "util-linux CVE-2026-3184 / PAM Smartcard Bypass" "$ERR" "installed util-linux=$ver; cross-check against the fixed version for CVE-2026-3184 manually (unverifiable version string in original report)"
}

chk_W02940458() { # logind poweroff bypass allow_active
    local f="/usr/share/polkit-1/actions/org.freedesktop.login1.policy"
    if [[ ! -f "$f" ]]; then
        record W02940458 "logind Poweroff Bypasses Auth (allow_active=yes)" "$ERR" "$f not found"
        return
    fi
    local hit
    hit=$(grep -A4 'power-off-multiple-sessions' "$f" | grep -c 'allow_active>yes')
    if [[ "$hit" -gt 0 ]]; then
        record W02940458 "logind Poweroff Bypasses Auth (allow_active=yes)" "$VULN" "power-off-multiple-sessions allow_active=yes"
    else
        record W02940458 "logind Poweroff Bypasses Auth (allow_active=yes)" "$OK" "allow_active is not 'yes' for multiple-sessions poweroff action"
    fi
}

chk_E01270148() { # remove_vim.sh unsafe removal
    local f="/usr/client/remove_vim.sh"
    if [[ ! -f "$f" ]]; then
        record E01270148 "remove_vim.sh Unsafe Package Removal" "$ERR" "$f not found"
        return
    fi
    local has_lock has_purge
    grep -q 'flock' "$f" && has_lock=yes || has_lock=no
    grep -q -- '--purge' "$f" && has_purge=yes || has_purge=no
    if [[ "$has_lock" == "no" ]]; then
        record E01270148 "remove_vim.sh Unsafe Package Removal" "$VULN" "no flock/apt-lock handling found; --purge used=$has_purge"
    else
        record E01270148 "remove_vim.sh Unsafe Package Removal" "$OK" "lock handling present"
    fi
}

chk_S00300334() { # missing user documentation
    local docs
    docs=$( { dpkg -L boss-secure-update 2>/dev/null; dpkg -L bossapparmor 2>/dev/null; } | grep -Ei 'README|doc/.*guide')
    if [[ -z "$docs" ]]; then
        record S00300334 "Missing User-Facing Documentation for BOSS Packages" "$VULN" "no README/guide files found in package file lists"
    else
        record S00300334 "Missing User-Facing Documentation for BOSS Packages" "$OK" "$docs"
    fi
}

chk_S00320726() { # apt http instead of https
    local hits
    hits=$(grep -rE 'deb http://' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null)
    if [[ -n "$hits" ]]; then
        record S00320726 "APT Repositories Using HTTP Instead of HTTPS" "$VULN" "$(echo "$hits" | tr '\n' ';')"
    else
        record S00320726 "APT Repositories Using HTTP Instead of HTTPS" "$OK" "no plain-http deb lines found"
    fi
}

chk_W00120332() { # apt trust cdrom
    local f="/etc/apt/apt.conf.d/00trustcdrom"
    local val groups_out
    val=$(cat "$f" 2>/dev/null)
    groups_out=$(id -nG 2>/dev/null)
    if echo "$val" | grep -q 'true'; then
        record W00120332 "APT Trusts CDROM Repos Without Signature Check" "$VULN" "$val; current user groups: $groups_out"
    elif [[ -n "$val" ]]; then
        record W00120332 "APT Trusts CDROM Repos Without Signature Check" "$OK" "$val"
    else
        record W00120332 "APT Trusts CDROM Repos Without Signature Check" "$OK" "$f absent or empty (default apt behavior applies)"
    fi
}

chk_S02570756() { # kernel ring buffer unprivileged access
    if is_root; then
        record S02570756 "Unprivileged Access to Kernel Ring Buffer" "$ERR" "run as non-root user for a valid test"
        return
    fi
    if dmesg 2>&1 | head -1 | grep -qi 'permission denied'; then
        record S02570756 "Unprivileged Access to Kernel Ring Buffer" "$OK" "dmesg denied to unprivileged user"
    else
        record S02570756 "Unprivileged Access to Kernel Ring Buffer" "$VULN" "unprivileged dmesg succeeded (kernel.dmesg_restrict likely 0)"
    fi
}

chk_W03250393() { # firewall-guard auto-restore blocking maintenance
    local f="/usr/bin/firewall-guard.sh"
    if [[ ! -f "$f" ]]; then
        record W03250393 "firewall-guard.sh Auto-Restores Stopped Services" "$ERR" "$f not found"
        return
    fi
    if grep -q 'clamav-monitor' "$f" && grep -Eq 'restart|start' "$f"; then
        record W03250393 "firewall-guard.sh Auto-Restores Stopped Services" "$VULN" "script force-restarts clamav-monitor with no maintenance override"
    else
        record W03250393 "firewall-guard.sh Auto-Restores Stopped Services" "$OK" "no unconditional auto-restart pattern found"
    fi
}

chk_E00330127() { # python file auto-delete
    local f="/tmp/main_$$.py"
    echo "print('test')" > "$f"
    sleep 5
    if [[ -f "$f" ]]; then
        record E00330127 "Python Files Auto-Deleted After Creation" "$OK" "test file survived 5s in /tmp"
        rm -f "$f"
    else
        record E00330127 "Python Files Auto-Deleted After Creation" "$VULN" "test .py file was deleted within 5s (likely by ftype-extensions.sh security feature)"
    fi
}

chk_W00100330() { # ftype-extensions.sh auto delete
    local f="/tmp/test_$$.sh"
    echo "#!/bin/sh" > "$f"
    sleep 12
    if [[ -f "$f" ]]; then
        record W00100330 "ftype-extensions.sh Auto-Deletes Files" "$OK" "test .sh file survived 12s in /tmp"
        rm -f "$f"
    else
        record W00100330 "ftype-extensions.sh Auto-Deletes Files (by design)" "$VULN" "test .sh file auto-deleted (this is an intentional BOSS OS quarantine feature per evaluator notes, not a bug)"
    fi
}

chk_W02720351() { # seccomp / auditd inactive
    local seccomp auditd_stat
    seccomp=$(grep -i 'Seccomp:' /proc/self/status 2>/dev/null | awk '{print $2}')
    auditd_stat=$(systemctl is-active auditd 2>/dev/null)
    if [[ "$seccomp" == "0" || "$auditd_stat" != "active" ]]; then
        record W02720351 "Missing Seccomp Sandboxing / Inactive auditd" "$VULN" "seccomp=$seccomp auditd=${auditd_stat:-inactive}"
    else
        record W02720351 "Missing Seccomp Sandboxing / Inactive auditd" "$OK" "seccomp=$seccomp auditd=$auditd_stat"
    fi
}

chk_W00100212() { # touch "1" 1.txt file creation logic (shell quoting, not a real bug)
    record W00100212 "Unrestricted File Creation via Shell Redirection" "$ERR" "original PoC is a shell-quoting misunderstanding (touch \"1234567890\" 1.txt creates two files by normal argument-splitting behavior) - not independently scriptable as a vuln check; review manually"
}

###############################################################################
# GUI-only findings -> cannot be verified headlessly
###############################################################################
gui_findings() {
    local gui_list=(
        "W00100205|GUI Freeze on Fullscreen Terminal"
        "W00290141|Terminal Fullscreen Overlay Becomes Unresponsive"
        "E00100133|Desktop Folder Not Displayed After Creation"
        "W00350136|Password Change Dialog Rejects Valid Current Password"
        "N02970164|Characters App Corrupted Glyph Previews"
        "S00280304|Digital Wellbeing Screen Time Sync Incorrect"
        "S01170233|App Search Results Not Alphabetically Sorted"
        "S02760826|GCR Certificate Viewer Drag-and-Drop Fails"
        "E02840090|Contacts App Does Not Validate Phone Number Input"
        "S01340343|Desktop/Taskbar Icons Not Visible After Login"
        "E00250078|New Document Action Reopens Existing File"
        "W00410402|Passwords and Keys Shows Chromium Secret Without Reauth"
        "S00990411|Parental Control Accessible to Restricted User Post-Auth"
        "S01610301|World Clock Add-City Dialog Freezes on Alarm"
        "S01030139|Evince Previewer Symlink Arbitrary File Read (needs GUI file-open test)"
        "N01920125|Root Session File Modify Denied via GUI (gedit) Despite CLI Working"
    )
    for entry in "${gui_list[@]}"; do
        local id="${entry%%|*}" title="${entry#*|}"
        record "$id" "$title" "$GUI" "Requires interactive GUI reproduction per original PoC steps - not scriptable headlessly"
    done
}

###############################################################################
# Physical-access-only findings
###############################################################################
physical_findings() {
    local phys_list=(
        "W01970006|Unprotected FS Writable From External Live Environment"
        "W00310210|Offline Persistent Root Compromise via Unencrypted rootfs"
        "S00820378|Unprotected Kernel Boot Parameters (GRUB edit -> init=/bin/bash)"
    )
    for entry in "${phys_list[@]}"; do
        local id="${entry%%|*}" title="${entry#*|}"
        record "$id" "$title" "$PHY" "Requires physical/console access to boot media or GRUB edit menu - not scriptable remotely"
    done
}

###############################################################################
# Run everything
###############################################################################
run_all() {
    chk_S00320821; chk_S01300735; chk_W00160453; chk_S00430193; chk_S00540062
    chk_W00440269; chk_W03250362; chk_S00470744; chk_S01170630; chk_S00610800
    chk_secureboot_generic; chk_S00300753; chk_W03250365; chk_S00370746
    chk_S00980496; chk_S02340861; chk_W03250369; chk_S00660743; chk_S00300755
    chk_W00310044; chk_auditctl_norules; chk_W01780371; chk_W03250374
    chk_W00300388; chk_S02770143; chk_S01360640; chk_W03250390; chk_S01300757
    chk_S00560476; chk_W03250380; chk_W00400299; chk_W00370381; chk_W03290454
    chk_tls_weak; chk_kernel_cve; chk_W00130515; chk_S00280760
    chk_W00440384_S00280763; chk_W02720391; chk_S01640841; chk_W00440476
    chk_S00300822_S01620368; chk_S01300774; chk_S00570801; chk_S00460335
    chk_W01210329_W00120422; chk_N00220182; chk_N00120152; chk_S00560374
    chk_W02940458; chk_E01270148; chk_S00300334; chk_S00320726; chk_W00120332
    chk_S02570756; chk_W03250393; chk_E00330127; chk_W00100330; chk_W02720351
    chk_W00100212
    gui_findings
    physical_findings
}

###############################################################################
# Report
###############################################################################
print_report() {
    local vc=0 oc=0 gc=0 pc=0 ec=0

    if [[ "$CSV" -eq 1 ]]; then
        echo "ID,Title,Status,Detail"
    else
        printf "%-12s %-9s %s\n" "ID" "STATUS" "TITLE"
        printf '%.0s-' {1..100}; echo
    fi

    for row in "${RESULTS[@]}"; do
        IFS='|' read -r id title status detail <<< "$row"
        case "$status" in
            "$VULN") ((vc++));;
            "$OK") ((oc++));;
            "$GUI") ((gc++));;
            "$PHY") ((pc++));;
            "$ERR") ((ec++));;
        esac
        if [[ "$CSV" -eq 1 ]]; then
            printf '"%s","%s","%s","%s"\n' "$id" "${title//\"/\'}" "$status" "${detail//\"/\'}"
        else
            printf "%-12s %-9s %s\n" "$id" "$status" "$title"
            [[ -n "$detail" ]] && printf "             -> %s\n" "$detail"
        fi
    done

    if [[ "$CSV" -eq 0 ]]; then
        echo
        printf '%.0s-' {1..100}; echo
        echo "SUMMARY: VULNERABLE=$vc  NOT-PRESENT=$oc  MANUAL-GUI=$gc  MANUAL-PHYSICAL=$pc  CHECK-ERROR=$ec  TOTAL=${#RESULTS[@]}"
        if ! is_root; then
            echo
            echo "NOTE: Not running as root. Re-run with 'sudo $0' for a complete/accurate result -"
            echo "      several checks (auditd, /etc/shadow perms, dmesg, sudo -l, kernel lockdown) need root."
        fi
    fi
}

run_all
print_report
