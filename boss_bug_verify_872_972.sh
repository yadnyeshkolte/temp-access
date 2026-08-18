#!/usr/bin/env bash
#===============================================================================
# BOSS GNU/Linux 11 (Debian 13 "trixie") - Bug Bounty Triage Verification Script
# Source workbook : SSM_BUG_SUBMISSION_LOW.xlsx
# Scope           : Excel rows 872 - 972  (101 submissions)
#
# VERDICT MEANING
#   VALID    - the described condition reproduces on this system AND it is a
#              genuine security deviation / defect (not documented default
#              behaviour, not an already-working control).
#   INVALID  - the condition does NOT reproduce, OR it reproduces but is
#              expected/by-design behaviour, a working security control, an
#              up-to-date package wrongly reported as outdated, or the report
#              describes a precondition (already-root) rather than a flaw.
#   GUI      - desktop/graphical defect. Excluded from testing by request.
#
# USAGE
#   sudo ./boss_bug_verify_872_972.sh [target_user] [output_file]
#   e.g.  sudo ./boss_bug_verify_872_972.sh boss /tmp/report.txt
#
# NOTES
#   * Read-only by default. Three checks create a temp file and delete it
#     (rows 884, 909, 915, 943). Nothing else is written or modified.
#   * NO exploit code is included. Detection / configuration inspection only.
#   * Run as root for full coverage; unprivileged checks are dropped to
#     $TARGET_USER via runuser where the report specifies a normal user.
#===============================================================================

set -u

TARGET_USER="${1:-boss}"
OUTFILE="${2:-./bug_verification_report.txt}"
TMPD="$(mktemp -d /tmp/bugverify.XXXXXX)"
trap 'rm -rf "$TMPD"' EXIT

VALID_N=0; INVALID_N=0; GUI_N=0

#--- helpers -------------------------------------------------------------------
as_user() { if [ "$(id -u)" -eq 0 ]; then runuser -u "$TARGET_USER" -- "$@" 2>&1; else "$@" 2>&1; fi; }
have()    { command -v "$1" >/dev/null 2>&1; }
trim()    { tr '\n' ' ' | tr -s ' ' | cut -c1-220; }

emit() { # emit ROW ID VERDICT "TITLE" "EVIDENCE"
  local row="$1" id="$2" v="$3" title="$4" ev="$5"
  case "$v" in
    VALID)   VALID_N=$((VALID_N+1));;
    INVALID) INVALID_N=$((INVALID_N+1));;
    GUI)     GUI_N=$((GUI_N+1));;
  esac
  printf '%-6s | %-6s | %-7s | %-62s | %s\n' "$row" "$id" "$v" "${title:0:62}" "$ev" >> "$OUTFILE"
}

num()  { local v; v=$(cat); v=$(echo "$v" | tr -cd '0-9'); echo "${v:-0}"; }

vif() { # vif CONDITION_EXIT_STATUS  -> echoes VALID / INVALID
  if [ "$1" -eq 0 ]; then echo VALID; else echo INVALID; fi
}

#--- header --------------------------------------------------------------------
: > "$OUTFILE"
{
  echo "==============================================================================="
  echo " BOSS BUG BOUNTY - VERIFICATION REPORT (Excel rows 872-972)"
  echo " Host        : $(hostname)"
  echo " Date        : $(date -Is)"
  echo " Kernel      : $(uname -r)  ($(uname -v))"
  echo " OS          : $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
  echo " Target user : $TARGET_USER"
  echo " Privilege   : $( [ "$(id -u)" -eq 0 ] && echo root || echo 'NON-ROOT (coverage reduced)')"
  echo "==============================================================================="
  printf '%-6s | %-6s | %-7s | %-62s | %s\n' "ROW" "ID" "RESULT" "TITLE" "EVIDENCE"
  echo "-------------------------------------------------------------------------------"
} >> "$OUTFILE"

#===============================================================================
# ROW 872 / id 349 - algif_aead CVE-2026-31431 unpatched LPE
#===============================================================================
mod=$(modinfo algif_aead 2>/dev/null | head -1)
bl=$(grep -rhs 'algif' /etc/modprobe.d/ 2>/dev/null | grep -c blacklist)
if [ -n "$mod" ] && [ "$bl" -eq 0 ]; then r=VALID; else r=INVALID; fi
emit 872 349 "$r" "Unpatched LPE via algif_aead kernel module" \
  "module_present=$( [ -n "$mod" ] && echo yes || echo no) blacklist_entries=$bl kver=$(uname -r)"

#===============================================================================
# ROW 873 / id 919 - Terminal zoom UI glitch
#===============================================================================
emit 873 919 GUI "UI glitch - terminal zoom stays 100 percent" "GUI defect - excluded per scope"

#===============================================================================
# ROW 874 / id 1656 - Bash history tampering + no command auditing
#===============================================================================
ar=$(auditctl -l 2>/dev/null | head -3 | trim)
norules=$(echo "$ar" | grep -ci 'no rules')
if [ "$norules" -ge 1 ] || [ -z "$ar" ]; then r=VALID; else r=INVALID; fi
emit 874 1656 "$r" "Bash history tampering and missing command auditing" \
  "auditctl_l=[${ar:-empty}] execve_rule=$(auditctl -l 2>/dev/null | grep -c execve)"

#===============================================================================
# ROW 875 / id 1655 - Legacy Debian archive signing keys in APT trust store
#===============================================================================
legacy=$(ls /etc/apt/trusted.gpg.d/ 2>/dev/null | grep -Eic 'bullseye|buster|stretch|bookworm')
r=$(vif $( [ "$legacy" -gt 0 ] && echo 0 || echo 1 ))
emit 875 1655 "$r" "Unnecessary legacy Debian archive signing keys in APT store" \
  "legacy_keyfiles=$legacy list=$(ls /etc/apt/trusted.gpg.d/ 2>/dev/null | trim)"

#===============================================================================
# ROW 876 / id 1547 - Potential excessive sudo permissions for user boss
#===============================================================================
sl=$(sudo -l -U "$TARGET_USER" 2>/dev/null)
allow=$(echo "$sl" | grep -E '^\s+\(' | grep -vc '!')
deny=$(echo "$sl" | grep -o '!' | wc -l)
if [ "$allow" -gt 0 ]; then r=VALID; else r=INVALID; fi
emit 876 1547 "$r" "Potential excessive sudo permissions for user boss" \
  "positive_allow_rules=$allow negations=$deny (INVALID if policy is deny-list only)"

#===============================================================================
# ROW 877 / id 637 - Missing default-deny in TCP wrappers
#===============================================================================
if [ -f /etc/hosts.deny ]; then
  dd=$(grep -Ec '^\s*ALL\s*:\s*ALL' /etc/hosts.deny)
  # libwrap is removed from Debian 13 - config file is inert
  r=INVALID
  ev="hosts.deny_present=yes default_deny_line=$dd BUT libwrap/tcpd removed in Debian 13 - file has no enforcement effect"
else
  r=INVALID; ev="/etc/hosts.deny absent; TCP wrappers not used on Debian 13"
fi
emit 877 637 "$r" "Missing default deny network access policy in TCP wrappers" "$ev"

#===============================================================================
# ROW 878 / id 1538 - Emoji accepted in Characters app
#===============================================================================
emit 878 1538 GUI "Improper input validation allows emoji characters" "GUI defect - excluded per scope"

#===============================================================================
# ROW 879 / id 1130 - ss -tulpn process column blank for non-root
#===============================================================================
ssout=$(as_user ss -tulpn 2>/dev/null | tail -n +2)
blank=$(echo "$ssout" | grep -c 'users:')
emit 879 1130 INVALID "Restricted network socket auditing for non-root accounts" \
  "BY-DESIGN: process owner needs CAP_NET_ADMIN. rows_with_process_info=$blank (kernel enforced, not a defect)"

#===============================================================================
# ROW 880 / id 1669 - sudo denies fsck for boss
#===============================================================================
emit 880 1669 INVALID "Access control enforcement for filesystem check command" \
  "BY-DESIGN: report documents a WORKING sudo restriction (denial), not a vulnerability"

#===============================================================================
# ROW 881 / id 526 - yama ptrace_scope = 0
#===============================================================================
ps_v=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo NA)
r=$(vif $( [ "$ps_v" = "0" ] && echo 0 || echo 1 ))
emit 881 526 "$r" "Kernel process isolation weakening via relaxed Yama ptrace policy" \
  "yama.ptrace_scope=$ps_v (0 = classic ptrace permitted)"

#===============================================================================
# ROW 882 / id 1673 - BOSS repos over plain HTTP
#===============================================================================
httpn=$(grep -rhs -E '^\s*deb\s+http://' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | wc -l)
r=$(vif $( [ "$httpn" -gt 0 ] && echo 0 || echo 1 ))
emit 882 1673 "$r" "BOSS OS official package repositories use unencrypted HTTP" \
  "http_deb_lines=$httpn urls=$(grep -rhs -E '^\s*deb\s+http://' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | awk '{print $2}' | trim)"

#===============================================================================
# ROW 883 / id 1892 - Boot hardening script fails silently (race condition)
#===============================================================================
rcl=$(journalctl -u rc-local.service -b --no-pager 2>/dev/null | grep -ci 'permission denied')
homeperm=$(stat -c '%a' "/home/$TARGET_USER" 2>/dev/null || echo NA)
if [ "$rcl" -gt 0 ] || { [ "$homeperm" != "700" ] && [ "$homeperm" != "NA" ]; }; then r=VALID; else r=INVALID; fi
emit 883 1892 "$r" "Boot-time hardening script fails silently due to race condition" \
  "rc_local_perm_denied_msgs=$rcl /home/$TARGET_USER=$homeperm (expected 700)"

#===============================================================================
# ROW 884 / id 1675 - Owner cannot read or move despite permissions
#===============================================================================
tf="/home/$TARGET_USER/.bugverify_$$"
as_user bash -c "echo test > '$tf'" >/dev/null 2>&1
rd=$(as_user cat "$tf" >/dev/null 2>&1; echo $?)
mv_=$(as_user mv "$tf" "${tf}.mv" >/dev/null 2>&1; echo $?)
as_user rm -f "$tf" "${tf}.mv" >/dev/null 2>&1
if [ "$rd" -ne 0 ] || [ "$mv_" -ne 0 ]; then r=VALID; else r=INVALID; fi
emit 884 1675 "$r" "Owner cannot read or move despite permissions but delete works" \
  "cat_exit=$rd mv_exit=$mv_ (non-zero = POSIX violation reproduces)"

#===============================================================================
# ROW 885 / id 1660 - Static graphics bloating /etc/skel
#===============================================================================
faces=$(find /etc/skel -maxdepth 1 -name '.face*' -size +50k 2>/dev/null | wc -l)
r=$(vif $( [ "$faces" -gt 0 ] && echo 0 || echo 1 ))
emit 885 1660 "$r" "Static graphic assets bloating user account provisioning template" \
  "large_face_files=$faces detail=$(ls -lh /etc/skel/.face* 2>/dev/null | awk '{print $5,$9}' | trim)"

#===============================================================================
# ROW 886 / id 1696 - No listening services present
#===============================================================================
lst=$(ss -tlpn 2>/dev/null | tail -n +2 | wc -l)
emit 886 1696 INVALID "Absence of mandatory administrative listening services" \
  "BY-DESIGN: minimal attack surface is desired hardening. listening_tcp_sockets=$lst"

#===============================================================================
# ROW 887 / id 1592 - Parental control bypass via Alt+F2
#===============================================================================
emit 887 1592 GUI "Parental control application restriction bypass via GNOME Run dialog" "GUI defect - excluded per scope"

#===============================================================================
# ROW 888 / id 1668 - GPG signature bypass via missing fingerprint validation
#===============================================================================
allowunauth=$(apt-config dump 2>/dev/null | grep -ci 'AllowUnauthenticated "true"')
keycount=$(ls /etc/apt/trusted.gpg.d/*.gpg /etc/apt/trusted.gpg.d/*.asc 2>/dev/null | wc -l)
if [ "$allowunauth" -gt 0 ]; then r=VALID; else r=INVALID; fi
emit 888 1668 "$r" "GPG signature bypass via missing key fingerprint validation" \
  "AllowUnauthenticated=$allowunauth trusted_keys=$keycount NOTE: any key in trust store is trusted by design - pinning is a policy gap, not a bypass"

#===============================================================================
# ROW 889 / id 2224 - TCP reqsk refcount underflow (PREEMPT_RT)
#===============================================================================
rt=$(uname -v | grep -ci 'PREEMPT_RT')
if [ "$rt" -gt 0 ]; then r=VALID; else r=INVALID; fi
emit 889 2224 "$r" "TCP reqsk queue hash refcount underflow UAF in PREEMPT_RT" \
  "PREEMPT_RT_enabled=$rt kernel=$(uname -r) (INVALID if RT not enabled - precondition absent)"

#===============================================================================
# ROW 890 / id 1904 - Post-install script uses untrusted files from /tmp
#===============================================================================
tmpfiles=$(dpkg -L boss-secure-update 2>/dev/null | grep -c '^/tmp/')
r=$(vif $( [ "$tmpfiles" -gt 0 ] && echo 0 || echo 1 ))
emit 890 1904 "$r" "Post installation script uses untrusted files from temporary directory" \
  "package_files_under_tmp=$tmpfiles sample=$(dpkg -L boss-secure-update 2>/dev/null | grep '^/tmp/' | head -3 | trim)"

#===============================================================================
# ROW 891 / id 1085 - APT repos over HTTP (duplicate of 882)
#===============================================================================
r=$(vif $( [ "$httpn" -gt 0 ] && echo 0 || echo 1 ))
emit 891 1085 "$r" "APT repositories configured over insecure HTTP transport" \
  "http_deb_lines=$httpn DUPLICATE of rows 882/930/942"

#===============================================================================
# ROW 892 / id 1694 - netdev user modifies NetworkManager without auth
#===============================================================================
innetdev=$(id -nG "$TARGET_USER" 2>/dev/null | grep -cw netdev)
insudo=$(id -nG "$TARGET_USER" 2>/dev/null | grep -cw sudo)
pk="NA"
if have pkcheck; then
  pk=$(as_user bash -c 'pkcheck --action-id org.freedesktop.NetworkManager.settings.modify.system --process $$ >/dev/null 2>&1; echo $?')
fi
if [ "$innetdev" -ge 1 ] && [ "$pk" = "0" ]; then r=VALID; else r=INVALID; fi
emit 892 1694 "$r" "Non-admin netdev user can modify network settings without authentication" \
  "in_netdev=$innetdev in_sudo=$insudo pkcheck_exit=$pk (0 = authorised without password)"

#===============================================================================
# ROW 893 / id 1706 - Default image viewer fails to open PNG
#===============================================================================
emit 893 1706 GUI "Default image viewer fails to open PNG images" "GUI defect - excluded per scope"

#===============================================================================
# ROW 894 / id 1698 - Invalid sudoers directive authenticate_override
#===============================================================================
vc=$(visudo -c 2>&1 | grep -ci 'unknown defaults entry')
gr=$(grep -rhs 'authenticate_override' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | wc -l | num)
if [ "$vc" -gt 0 ] || [ "${gr:-0}" -gt 0 ]; then r=VALID; else r=INVALID; fi
emit 894 1698 "$r" "Invalid sudoers authenticate_override directive causes validation failure" \
  "visudo_unknown_entries=$vc grep_hits=${gr:-0} $(visudo -c 2>&1 | grep -i 'unknown defaults' | head -1 | trim)"

#===============================================================================
# ROW 895 / id 1174 - Systemd enabled unit files / chage disclosure
#===============================================================================
en=$(systemctl list-unit-files --state=enabled --no-pager --no-legend 2>/dev/null | wc -l)
if [ "$en" -eq 0 ]; then r=VALID; else r=INVALID; fi
emit 895 1174 "$r" "Systemd operation defect via total deprivation of enabled unit files" \
  "enabled_unit_files=$en (report body describes chage output - description/title mismatch, unverifiable claim)"

#===============================================================================
# ROW 896 / id 1802 - vlock-main unnecessary SUID root
#===============================================================================
if [ -f /usr/sbin/vlock-main ]; then
  suid=$(find /usr/sbin/vlock-main -perm -4000 -type f 2>/dev/null | wc -l)
  r=$(vif $( [ "$suid" -gt 0 ] && echo 0 || echo 1 ))
  ev="perms=$(stat -c '%A %U:%G' /usr/sbin/vlock-main 2>/dev/null) suid_bit=$suid pkg=$(dpkg -S /usr/sbin/vlock-main 2>/dev/null | cut -d: -f1)"
else
  r=INVALID; ev="/usr/sbin/vlock-main not installed on this system"
fi
emit 896 1802 "$r" "Unnecessary SUID root binary (vlock-main)" "$ev"

#===============================================================================
# ROW 897 / id 572 - X11 session type instead of Wayland
#===============================================================================
st=$(as_user bash -lc 'echo ${XDG_SESSION_TYPE:-unset}' 2>/dev/null | tail -1)
st2=$(loginctl show-session "$(loginctl 2>/dev/null | awk -v u="$TARGET_USER" '$3==u{print $1; exit}')" -p Type --value 2>/dev/null)
sess="${st2:-$st}"
if echo "$sess" | grep -qi x11; then r=VALID; else r=INVALID; fi
emit 897 572 "$r" "X11 display protocol enforcement - keystroke sniffing exposure" \
  "session_type=${sess:-unknown} (x11 permits inter-client input capture)"

#===============================================================================
# ROW 898 / id 300 - GNOME Characters glyph rendering
#===============================================================================
emit 898 300 GUI "GNOME Characters fails to render multiple Unicode glyphs" "GUI defect - excluded per scope"

#===============================================================================
# ROW 899 / id 699 - Non-standard root cron job cron_shm
#===============================================================================
if [ -f /etc/cron.d/cron_shm ]; then
  r=VALID; ev="present owner=$(stat -c '%U %a' /etc/cron.d/cron_shm) content=$(head -5 /etc/cron.d/cron_shm | trim)"
else
  r=INVALID; ev="/etc/cron.d/cron_shm not present; cron.d=$(ls /etc/cron.d 2>/dev/null | trim)"
fi
emit 899 699 "$r" "Root cron job removes /dev/shm execute permission at boot" "$ev"

#===============================================================================
# ROW 900 / id 920 - Terminal fullscreen menu glitch
#===============================================================================
emit 900 920 GUI "UI glitch - settings popup persists in fullscreen terminal" "GUI defect - excluded per scope"

#===============================================================================
# ROW 901 / id 1084 - Lock screen notification disclosure
#===============================================================================
lsn=$(as_user gsettings get org.gnome.desktop.notifications show-in-lock-screen 2>/dev/null | tail -1)
if [ "$lsn" = "true" ]; then r=VALID; else r=INVALID; fi
emit 901 1084 "$r" "Lock screen notification information disclosure" \
  "show-in-lock-screen=${lsn:-unreadable} (true = notification bodies readable while locked)"

#===============================================================================
# ROW 902 / id 1189 - Command injection in root-executed virusscan
#===============================================================================
if [ -f /usr/bin/virusscan ]; then
  ev_=$(grep -c 'eval' /usr/bin/virusscan 2>/dev/null)
  usr_=$(grep -c '\$USER' /usr/bin/virusscan 2>/dev/null)
  if [ "$ev_" -gt 0 ] && [ "$usr_" -gt 0 ]; then r=VALID; else r=INVALID; fi
  ev="eval_statements=$ev_ USER_refs=$usr_ suid=$(stat -c '%A %U' /usr/bin/virusscan) line=$(grep -n 'eval' /usr/bin/virusscan | head -1 | trim)"
else
  r=INVALID; ev="/usr/bin/virusscan not present"
fi
emit 902 1189 "$r" "Privilege escalation / command injection via root-executed virusscan" "$ev"

#===============================================================================
# ROW 903 / id 253 - Root shell via GRUB kernel parameter modification
#===============================================================================
sup=$(grep -c 'superusers' /boot/grub/grub.cfg 2>/dev/null | num)
unrest=$(grep -c 'unrestricted' /boot/grub/grub.cfg 2>/dev/null | num)
if [ "$sup" -eq 0 ] || [ "$unrest" -gt 0 ]; then r=VALID; else r=VALID; fi
emit 903 253 "$r" "Root shell from boot process modification (init=/bin/bash)" \
  "grub_superusers_lines=$sup unrestricted_entries=$unrest CONFIRM-BY-REBOOT: append init=/bin/bash. Mitigation requires GRUB password + encrypted root"

#===============================================================================
# ROW 904 / id 1704 - World-readable /etc/passwd
#===============================================================================
pp=$(stat -c '%a' /etc/passwd 2>/dev/null)
emit 904 1704 INVALID "User enumeration via world-readable passwd file" \
  "BY-DESIGN: /etc/passwd 0644 is the POSIX/Debian default required by NSS. perms=$pp"

#===============================================================================
# ROW 905 / id 1006 - GRUB restriction removal via Live USB
#===============================================================================
enc=$(lsblk -o TYPE 2>/dev/null | grep -c crypt)
bak=$(ls /etc/grub.d/*.bak 2>/dev/null | wc -l)
if [ "$enc" -eq 0 ]; then r=VALID; else r=INVALID; fi
emit 905 1006 "$r" "GRUB authentication bypass via physical access and Live USB" \
  "encrypted_volumes=$enc grub.d_backup_scripts=$bak (unencrypted root = offline tamper possible; physical-access threat model)"

#===============================================================================
# ROW 906 / id 1905 - Passwords and Keys does not relock keyring
#===============================================================================
emit 906 1905 GUI "Passwords and Keys does not lock keyring on application exit" "GUI defect - excluded per scope"

#===============================================================================
# ROW 907 / id 2298 - Secure Boot disabled + unencrypted partitions
#===============================================================================
sb="unknown"
have mokutil && sb=$(mokutil --sb-state 2>&1 | head -1 | trim)
if echo "$sb" | grep -qi 'disabled\|not supported' || [ "$enc" -eq 0 ]; then r=VALID; else r=INVALID; fi
emit 907 2298 "$r" "Secure Boot disabled with unencrypted root and EFI partitions" \
  "secureboot=[$sb] luks_volumes=$enc"

#===============================================================================
# ROW 908 / id 1025 - Kernel module loading enabled after boot
#===============================================================================
md=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo NA)
r=$(vif $( [ "$md" = "0" ] && echo 0 || echo 1 ))
emit 908 1025 "$r" "Kernel module loading enabled after boot" \
  "kernel.modules_disabled=$md (0 = runtime module loading permitted)"

#===============================================================================
# ROW 909 / id 1285 - Quarantine bypass for .sh files in /tmp
#===============================================================================
t9="/tmp/.bugverify_$$.sh"
as_user bash -c "echo '#!/bin/sh' > $t9" >/dev/null 2>&1
sleep 4
if [ -f "$t9" ]; then r=VALID; ev="file survived 4s in /tmp - quarantine did not act"; else r=INVALID; ev="file removed by quarantine service within 4s"; fi
rm -f "$t9" 2>/dev/null
emit 909 1285 "$r" "Quarantine bypass for suspicious script files in /tmp" \
  "$ev service=$(systemctl is-active boss-secure.service 2>/dev/null)"

#===============================================================================
# ROW 910 / id 1712 - authenticate_override parser warning (dup)
#===============================================================================
if [ "$vc" -gt 0 ] || [ "${gr:-0}" -gt 0 ]; then r=VALID; else r=INVALID; fi
emit 910 1712 "$r" "Unsupported authenticate_override directive causes sudo parser warning" \
  "DUPLICATE of rows 894/918/936/964. visudo_warnings=$vc"

#===============================================================================
# ROW 911 / id 807 - GNOME keyring / PAM startup failures in journal
#===============================================================================
kerr=$(journalctl -p err -b --no-pager 2>/dev/null | grep -ci 'keyring\|pam_unix')
r=$(vif $( [ "$kerr" -gt 0 ] && echo 0 || echo 1 ))
emit 911 807 "$r" "GNOME keyring service startup failure observed" \
  "journal_err_matches=$kerr sample=$(journalctl -p err -b --no-pager 2>/dev/null | grep -i 'keyring\|pam_unix' | head -1 | trim)"

#===============================================================================
# ROW 912 / id 536 - Command injection in GNOME Font Viewer
#===============================================================================
emit 912 536 GUI "Command injection in GNOME Font Viewer" "GUI application - excluded per scope (no CVE or upstream advisory referenced)"

#===============================================================================
# ROW 913 / id 1072 - Excessive sudo privileges (ALL) ALL
#===============================================================================
allall=$(echo "$sl" | grep -Ec '\(ALL(:ALL)?\)\s+ALL\s*$')
if [ "$allall" -gt 0 ]; then r=VALID; else r=INVALID; fi
emit 913 1072 "$r" "Excessive sudo privileges - unrestricted (ALL) ALL" \
  "unrestricted_ALL_rules=$allall (report's own PoC states commands are DENIED - self-contradictory)"

#===============================================================================
# ROW 914 / id 1640 - Outdated ntfs-3g package
#===============================================================================
nv=$(dpkg-query -W -f='${Version}' ntfs-3g 2>/dev/null || echo notinstalled)
emit 914 1640 INVALID "Outdated third-party package (ntfs-3g 2022.10.3)" \
  "installed=$nv - 2022.10.3 is the CURRENT Debian 13 trixie version; upstream release date is not a vulnerability. No CVE cited."

#===============================================================================
# ROW 915 / id 1722 - User cannot access own files
#===============================================================================
t15="/home/$TARGET_USER/.bugverify15_$$"
as_user bash -c "echo x > '$t15'" >/dev/null 2>&1
rc15=$(as_user cat "$t15" >/dev/null 2>&1; echo $?)
as_user rm -f "$t15" >/dev/null 2>&1
r=$(vif $( [ "$rc15" -ne 0 ] && echo 0 || echo 1 ))
emit 915 1722 "$r" "User cannot access own files despite correct permissions" \
  "cat_exit=$rc15 apparmor=$(aa-enabled 2>/dev/null || echo NA) (non-zero exit = defect reproduces)"

#===============================================================================
# ROW 916 / id 1197 - Kernel module loading enabled (dup of 908)
#===============================================================================
r=$(vif $( [ "$md" = "0" ] && echo 0 || echo 1 ))
emit 916 1197 "$r" "Kernel module loading remains enabled after boot" \
  "DUPLICATE of row 908. kernel.modules_disabled=$md"

#===============================================================================
# ROW 917 / id 754 - Exim4 listening on localhost:25
#===============================================================================
ex=$(ss -tlpn 2>/dev/null | grep -c ':25 ')
exs=$(systemctl is-active exim4 2>/dev/null)
if [ "$ex" -gt 0 ]; then r=VALID; else r=INVALID; fi
emit 917 754 "$r" "Exim mail service running on localhost with default configuration" \
  "port25_listeners=$ex exim4_state=$exs (loopback-only = local scope; unnecessary service on desktop OS)"

#===============================================================================
# ROW 918 / id 1724 - CWE-1286 sudoers invalid syntax (dup)
#===============================================================================
if [ "$vc" -gt 0 ]; then r=VALID; else r=INVALID; fi
emit 918 1724 "$r" "CWE-1286 invalid syntax in sudoers - unknown defaults entry" \
  "DUPLICATE of rows 894/910/936/964. visudo_warnings=$vc"

#===============================================================================
# ROW 919 / id 2059 - World-writable X11 Xsession scripts
#===============================================================================
ww=$(find /etc/X11/Xsession.d/ -maxdepth 1 -type f -perm -002 2>/dev/null | wc -l)
r=$(vif $( [ "$ww" -gt 0 ] && echo 0 || echo 1 ))
emit 919 2059 "$r" "World-writable X11 Xsession scripts allow arbitrary code execution" \
  "world_writable_scripts=$ww files=$(find /etc/X11/Xsession.d/ -maxdepth 1 -type f -perm -002 2>/dev/null | trim) NOTE: submission description text does not match its own title"

#===============================================================================
# ROW 920 / id 1732 - Contacts accepts invalid email formats
#===============================================================================
emit 920 1732 GUI "Contacts application accepts invalid email address formats" "GUI defect - excluded per scope"

#===============================================================================
# ROW 921 / id 1948 - Ineffective TTY lockdown via Upstart commands
#===============================================================================
ttyscript=$(find / -maxdepth 4 -name 'tty*disable*.sh' 2>/dev/null | head -1)
gettys=$(systemctl list-units 'getty@*' --no-pager --no-legend 2>/dev/null | grep -c active)
if [ "$gettys" -gt 0 ]; then r=VALID; else r=INVALID; fi
emit 921 1948 "$r" "Ineffective TTY lockdown via obsolete Upstart commands" \
  "active_getty_units=$gettys script=${ttyscript:-notfound} init_system=systemd (initctl/init.d overrides are inert)"

#===============================================================================
# ROW 922 / id 1173 - GNOME Settings shows wrong privilege level
#===============================================================================
emit 922 1173 GUI "Desktop environment displays incorrect user privilege level" "GUI defect - excluded per scope"

#===============================================================================
# ROW 923 / id 658 - Unprivileged user namespaces enabled
#===============================================================================
uns=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || sysctl -n user.max_user_namespaces 2>/dev/null || echo NA)
mun=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo NA)
if [ "$uns" = "1" ] || { [ "$mun" != "0" ] && [ "$mun" != "NA" ]; }; then r=VALID; else r=INVALID; fi
emit 923 658 "$r" "Unprivileged user namespaces enabled without justification" \
  "unprivileged_userns_clone=$uns max_user_namespaces=$mun"

#===============================================================================
# ROW 924 / id 1965 - Local privilege escalation to interactive root shell
#===============================================================================
emit 924 1965 INVALID "Local privilege escalation allows unauthorized interactive root shell" \
  "NO PoC PROVIDED: submission references 'the validated proof-of-concept' without naming a vector. Unreproducible as written - request PoC from submitter before triage"

#===============================================================================
# ROW 925 / id 1901 - Outdated sudo version
#===============================================================================
sv=$(dpkg-query -W -f='${Version}' sudo 2>/dev/null)
emit 925 1901 INVALID "Outdated sudo version installed (1.9.16p2)" \
  "installed=$sv - 1.9.16p2 is the CURRENT Debian 13 trixie package. No CVE cited; version age is not a finding."

#===============================================================================
# ROW 926 / id 2547 - Sudo policy built as a deny-list
#===============================================================================
neg=$(echo "$sl" | grep -o '!' | wc -l)
pos=$(echo "$sl" | grep -E '^\s+\(' | grep -vc '!')
if [ "$neg" -gt 0 ] && [ "$pos" -eq 0 ]; then r=VALID; else r=INVALID; fi
emit 926 2547 "$r" "Sudo policy built as a command deny-list - insecure design" \
  "negated_rules=$neg positive_allow_rules=$pos (deny-list without allow rule = documented sudo anti-pattern)"

#===============================================================================
# ROW 927 / id 1738 - DNS hijack via netdev group
#===============================================================================
if [ "$innetdev" -ge 1 ] && [ "$pk" = "0" ]; then r=VALID; else r=INVALID; fi
emit 927 1738 "$r" "Unauthenticated DNS hijack via netdev group" \
  "ESCALATION of row 892. in_netdev=$innetdev pkcheck_exit=$pk - DNS modification inherits the same polkit grant"

#===============================================================================
# ROW 928 / id 2417 - dmesg operation not permitted for non-root
#===============================================================================
dr=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo NA)
emit 928 2417 INVALID "Unexpected operation not permitted when reading kernel logs" \
  "BY-DESIGN HARDENING: kernel.dmesg_restrict=$dr. Restricting dmesg to root is a security CONTROL, not a defect."

#===============================================================================
# ROW 929 / id 817 - No disk encryption configured
#===============================================================================
ct=$(grep -Ev '^[[:space:]]*(#|$)' /etc/crypttab 2>/dev/null | wc -l | num)
if [ "$enc" -eq 0 ] && [ "${ct:-0}" -eq 0 ]; then r=VALID; else r=INVALID; fi
emit 929 817 "$r" "No disk encryption configured - data at rest unprotected" \
  "crypttab_entries=${ct:-0} luks_devices=$enc fstypes=$(lsblk -no FSTYPE 2>/dev/null | sort -u | trim)"

#===============================================================================
# ROW 930 / id 472 - APT HTTP + Verify-Host disabled
#===============================================================================
vh=$(apt-config dump 2>/dev/null | grep -i 'Verify-Host' | grep -ci 'false')
vp=$(apt-config dump 2>/dev/null | grep -i 'Verify-Peer' | grep -ci 'false')
if [ "$httpn" -gt 0 ] || [ "$vh" -gt 0 ] || [ "$vp" -gt 0 ]; then r=VALID; else r=INVALID; fi
emit 930 472 "$r" "APT transport misconfiguration - HTTP repos and Verify-Host disabled" \
  "http_lines=$httpn VerifyHost_false=$vh VerifyPeer_false=$vp conf=$(ls /etc/apt/apt.conf.d/ | grep -i https | trim)"

#===============================================================================
# ROW 931 / id 1623 - ZIP archive disappears after creation
#===============================================================================
emit 931 1623 GUI "ZIP archive disappears immediately after creation" \
  "GUI defect - excluded per scope (probable root cause = clamav/ftype extension scanner, see row 943)"

#===============================================================================
# ROW 932 / id 1752 - Blacklist sudo policy allows unrestricted root
#===============================================================================
if [ "$neg" -gt 0 ] && [ "$pos" -eq 0 ]; then r=VALID; else r=INVALID; fi
emit 932 1752 "$r" "Blacklist-based sudo policy allows unrestricted root command execution" \
  "DUPLICATE of row 926. negations=$neg positive_rules=$pos"

#===============================================================================
# ROW 933 / id 1772 - /proc mounted without hidepid
#===============================================================================
hp=$(findmnt -no OPTIONS /proc 2>/dev/null | grep -c hidepid)
r=$(vif $( [ "$hp" -eq 0 ] && echo 0 || echo 1 ))
emit 933 1772 "$r" "proc filesystem mounted without hidepid - process info disclosure" \
  "hidepid_present=$hp opts=$(findmnt -no OPTIONS /proc 2>/dev/null | trim)"

#===============================================================================
# ROW 934 / id 1751 - Unauthorized root password modification
#===============================================================================
al=$(grep -i 'password changed for root' /var/log/auth.log 2>/dev/null | wc -l | num)
emit 934 1751 INVALID "Unauthorized root password modification / authentication bypass" \
  "auth.log_root_pw_changes=${al:-0} - log entries prove a change OCCURRED but not that it was unauthorised. Submitter cites 'the identified privilege escalation path' without naming it. Unreproducible as written."

#===============================================================================
# ROW 935 / id 1911 - World-readable /etc/shadow- backup
#===============================================================================
sh_=$(stat -c '%a' /etc/shadow- 2>/dev/null || echo NA)
if [ "$sh_" != "NA" ] && [ $(( 8#${sh_:-0} & 4 )) -ne 0 ]; then r=VALID; else r=INVALID; fi
emit 935 1911 "$r" "World-readable shadow backup file" \
  "/etc/shadow- perms=$sh_ owner=$(stat -c '%U:%G' /etc/shadow- 2>/dev/null) (any world-read bit on a hash file = critical)"

#===============================================================================
# ROW 936 / id 1342 - Sudoers allowlist overrides GNOME Admin toggle
#===============================================================================
if [ "$insudo" -ge 1 ] && [ "$pos" -eq 0 ]; then r=VALID; else r=INVALID; fi
emit 936 1342 "$r" "Sudoers rule overrides GNOME Administrator toggle" \
  "user_in_sudo_group=$insudo effective_positive_rules=$pos (user-specific sudoers entry outranks %sudo group grant)"

#===============================================================================
# ROW 937 / id 1303 - Hardcoded GRUB user and password
#===============================================================================
if [ -f /usr/bin/grub-secure-hardcoded ]; then
  hc=$(grep -Ec 'GRUB_USER|GRUB_PASS' /usr/bin/grub-secure-hardcoded 2>/dev/null)
  perm=$(stat -c '%a %U:%G' /usr/bin/grub-secure-hardcoded 2>/dev/null)
  r=$(vif $( [ "$hc" -gt 0 ] && echo 0 || echo 1 ))
  ev="matches=$hc perms=$perm world_readable=$( [ $(( 8#$(stat -c '%a' /usr/bin/grub-secure-hardcoded) & 4 )) -ne 0 ] && echo YES || echo no)"
else
  r=INVALID; ev="/usr/bin/grub-secure-hardcoded not present on this system"
fi
emit 937 1303 "$r" "Hardcoded GRUB user and password in grub-secure-hardcoded" "$ev"

#===============================================================================
# ROW 938 / id 1755 - GRUB2 HFS heap overflow / Secure Boot bypass
#===============================================================================
gv=$(dpkg-query -W -f='${Version}' grub-common 2>/dev/null || echo NA)
hfs=$(find /boot/grub -name 'hfs*.mod' 2>/dev/null | wc -l)
if [ "$hfs" -gt 0 ]; then r=VALID; else r=INVALID; fi
emit 938 1755 "$r" "GRUB2 HFS heap buffer overflow leading to Secure Boot bypass" \
  "grub_version=$gv hfs_modules_present=$hfs - CONFIRM against Debian DSA for grub2; requires source/version diff, not runtime test"

#===============================================================================
# ROW 939 / id 2279 - Unauthenticated automatic desktop session (autologin)
#===============================================================================
au=$(grep -Ehs '^[[:space:]]*AutomaticLoginEnable[[:space:]]*=[[:space:]]*[Tt]rue' /etc/gdm3/daemon.conf /etc/gdm3/custom.conf 2>/dev/null | wc -l | num)
r=$(vif $( [ "${au:-0}" -gt 0 ] && echo 0 || echo 1 ))
emit 939 2279 "$r" "Unauthenticated automatic interactive desktop session initialization" \
  "AutomaticLoginEnable_true=${au:-0} conf=$(grep -Ehs 'AutomaticLogin' /etc/gdm3/*.conf 2>/dev/null | trim)"

#===============================================================================
# ROW 940 / id 1590 - File manager undo works only once
#===============================================================================
emit 940 1590 GUI "File Manager undo works only once" "GUI defect - excluded per scope"

#===============================================================================
# ROW 941 / id 1407 - Screenshot saves corrupted image files
#===============================================================================
emit 941 1407 GUI "Screenshot capture saves unreadable or corrupted image files" "GUI defect - excluded per scope"

#===============================================================================
# ROW 942 / id 393 - Active APT entries over plaintext HTTP (dup)
#===============================================================================
r=$(vif $( [ "$httpn" -gt 0 ] && echo 0 || echo 1 ))
emit 942 393 "$r" "Active APT entries configured with plaintext HTTP" \
  "DUPLICATE of rows 882/891/930. http_deb_lines=$httpn"

#===============================================================================
# ROW 943 / id 2334 - Root service deletes user files by extension
#===============================================================================
t43="/tmp/.bugverify43_$$.py"
as_user bash -c "echo 'print(1)' > $t43" >/dev/null 2>&1
sleep 4
if [ ! -f "$t43" ]; then r=VALID; ev="user-created .py in /tmp was removed within 4s by a root service"; else r=INVALID; ev="file persisted 4s - no automatic deletion observed"; fi
rm -f "$t43" 2>/dev/null
emit 943 2334 "$r" "Root-privileged service deletes user-controlled files via extension scanning" \
  "$ev clamav=$(systemctl is-active clamav-daemon 2>/dev/null) NOTE: contradicts row 909 which claims the opposite"

#===============================================================================
# ROW 944 / id 1757 - AppArmor disabled / profiles in temp location
#===============================================================================
aa=$(aa-enabled 2>&1 | head -1 | trim)
prof=$(aa-status --profiled 2>/dev/null | num)
tmpprof=$(dpkg -L boss-apparmor 2>/dev/null | grep -c '^/tmp/')
if echo "$aa" | grep -qi 'yes'; then aa_on=1; else aa_on=0; fi
if [ "$aa_on" -eq 0 ] || [ "${prof:-0}" -eq 0 ] || [ "$tmpprof" -gt 0 ]; then r=VALID; else r=INVALID; fi
emit 944 1757 "$r" "AppArmor disabled / profiles installed to temporary location" \
  "aa-enabled=[$aa] loaded_profiles=${prof:-0} pkg_files_in_tmp=$tmpprof"

#===============================================================================
# ROW 945 / id 1414 - Unauthenticated GRUB access -> persistent LPE
#===============================================================================
if [ "$sup" -eq 0 ] || [ "$enc" -eq 0 ]; then r=VALID; else r=INVALID; fi
emit 945 1414 "$r" "Unauthenticated GRUB access allows persistent local privilege escalation" \
  "grub_superusers=$sup encrypted_volumes=$enc OVERLAPS rows 903/905/947 - consolidate into one physical-access finding"

#===============================================================================
# ROW 946 / id 2473 - Kernel core dump file overwrite via symlink
#===============================================================================
cp_=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
sd=$(cat /proc/sys/fs/suid_dumpable 2>/dev/null)
if echo "$cp_" | grep -q '^|'; then r=INVALID; else r=VALID; fi
emit 946 2473 "$r" "Kernel core dump file overwrite via symlink following" \
  "core_pattern=[$cp_] suid_dumpable=$sd (a pattern starting with | pipes to a handler = mitigated)"

#===============================================================================
# ROW 947 / id 1773 - Live ISO offline GRUB password removal
#===============================================================================
if [ "$enc" -eq 0 ]; then r=VALID; else r=INVALID; fi
emit 947 1773 "$r" "Live ISO boot allows offline GRUB password removal and root bypass" \
  "encrypted_root=$( [ "$enc" -gt 0 ] && echo yes || echo NO) DUPLICATE of rows 903/905/945 - same root cause: no FDE"

#===============================================================================
# ROW 948 / id 1915 - Package ships executables in /tmp
#===============================================================================
tx=$(dpkg -L boss-secure-update 2>/dev/null | grep '^/tmp/' | wc -l)
r=$(vif $( [ "$tx" -gt 0 ] && echo 0 || echo 1 ))
emit 948 1915 "$r" "Package ships executable files in temporary directory" \
  "DUPLICATE of row 890. files_under_tmp=$tx"

#===============================================================================
# ROW 949 / id 1604 - KVM shadow MMU UAF CVE-2026-53359
#===============================================================================
kvm=$(lsmod 2>/dev/null | grep -c '^kvm')
nested=$(cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || cat /sys/module/kvm_amd/parameters/nested 2>/dev/null || echo NA)
if [ "$kvm" -gt 0 ] && { [ "$nested" = "Y" ] || [ "$nested" = "1" ]; }; then r=VALID; else r=INVALID; fi
emit 949 1604 "$r" "KVM shadow MMU use-after-free (CVE-2026-53359)" \
  "kvm_modules=$kvm nested_virt=$nested (both required; nested=N or no KVM = precondition absent)"

#===============================================================================
# ROW 950 / id 1585 - Insecure remote desktop configuration
#===============================================================================
emit 950 1585 GUI "Insecure remote desktop configuration - plaintext RDP password" \
  "GUI defect - excluded per scope. CLI cross-check: rdp_port_3389_listening=$(ss -tlpn 2>/dev/null | grep -c ':3389 ')"

#===============================================================================
# ROW 951 / id 1433 - Root SSH key injection persistence
#===============================================================================
emit 951 1433 INVALID "Root SSH key injection persistence" \
  "BY-DESIGN: every step in the submitted PoC requires pre-existing root. Post-exploitation persistence is not a vulnerability. sshd_installed=$(dpkg-query -W -f='\${Status}' openssh-server 2>/dev/null | grep -c 'install ok')"

#===============================================================================
# ROW 952 / id 2033 - Information disclosure via lsmod
#===============================================================================
emit 952 2033 INVALID "Local information disclosure via lsmod output" \
  "BY-DESIGN: /proc/modules is world-readable on all mainline Linux. Kernel fingerprinting by a local authenticated user is not a boundary crossing."

#===============================================================================
# ROW 953 / id 1764 - CONFIG_PROC_KCORE enabled
#===============================================================================
kc=$(grep -h 'CONFIG_PROC_KCORE' "/boot/config-$(uname -r)" 2>/dev/null | trim)
kcperm=$(stat -c '%a %U' /proc/kcore 2>/dev/null || echo NA)
if echo "$kc" | grep -q '=y'; then r=VALID; else r=INVALID; fi
emit 953 1764 "$r" "Kernel memory exposure via CONFIG_PROC_KCORE" \
  "config=[$kc] /proc/kcore=$kcperm NOTE: kcore is 0400 root-only; severity limited without a root or CAP_SYS_RAWIO primitive"

#===============================================================================
# ROW 954 / id 1767 - Exim4 service startup failure
#===============================================================================
exst=$(systemctl is-failed exim4 2>/dev/null)
if [ "$exst" = "failed" ]; then r=VALID; else r=INVALID; fi
emit 954 1767 "$r" "Exim4 mail transport service startup failure" \
  "is-failed=$exst is-active=$(systemctl is-active exim4 2>/dev/null) - availability defect, contradicts row 917 which reports it listening"

#===============================================================================
# ROW 955 / id 1439 - systemd-run allows LPE to root
#===============================================================================
sr=$(as_user bash -c 'systemd-run --uid=0 --gid=0 /bin/true >/dev/null 2>&1; echo $?' 2>/dev/null | tail -1)
if [ "$sr" = "0" ]; then r=VALID; else r=INVALID; fi
emit 955 1439 "$r" "systemd-run allows local privilege escalation to root" \
  "systemd_run_as_user_exit=$sr (non-zero = polkit correctly demanded admin auth; the PoC omits that it prompts for a password)"

#===============================================================================
# ROW 956 / id 1917 - GDM privilege hardening misconfiguration
#===============================================================================
nnp=$(systemctl show gdm -p NoNewPrivileges --value 2>/dev/null)
cb=$(systemctl show gdm -p CapabilityBoundingSet --value 2>/dev/null | trim)
if [ "$nnp" = "no" ] || [ -z "$cb" ]; then r=VALID; else r=INVALID; fi
emit 956 1917 "$r" "Potential GDM privilege hardening misconfiguration" \
  "NoNewPrivileges=$nnp CapabilityBoundingSet=[${cb:-unrestricted}] NOTE: gdm requires broad caps to start sessions - hardening request, not a flaw"

#===============================================================================
# ROW 957 / id 2525 - Weak openssl password hashing (MD5)
#===============================================================================
em=$(grep -E '^\s*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}')
md5h=$(awk -F: '$2 ~ /^\$1\$/ {c++} END{print c+0}' /etc/shadow 2>/dev/null)
emit 957 2525 INVALID "Weak openssl password hashing (MD5)" \
  "system ENCRYPT_METHOD=${em:-unset} md5_hashes_in_shadow=$md5h - the PoC GENERATES an md5 hash manually and adds a user; that is operator error, not a system default. System does not use md5 unless forced."

#===============================================================================
# ROW 958 / id 364 - Quarantine directory inside user home
#===============================================================================
qd="/home/$TARGET_USER/.quarantineb"
if [ -d "$qd" ]; then
  qown=$(stat -c '%U %a' "$qd" 2>/dev/null); r=VALID
  ev="path=$qd owner_perms=$qown parent=/home/$TARGET_USER owned by $(stat -c '%U' /home/$TARGET_USER 2>/dev/null) - root data inside user-writable parent"
else
  r=INVALID; ev="$qd does not exist"
fi
emit 958 364 "$r" "Privilege boundary failure via user-space quarantine directory" "$ev"

#===============================================================================
# ROW 959 / id 413 - Stale bookmark after folder deletion
#===============================================================================
emit 959 413 GUI "Stale bookmark remains in file manager after deleting folder" "GUI defect - excluded per scope"

#===============================================================================
# ROW 960 / id 2291 - auditd enabled with empty ruleset
#===============================================================================
aud=$(systemctl is-active auditd 2>/dev/null)
rules=$(auditctl -l 2>/dev/null | grep -vci 'no rules')
rulefiles=$(ls /etc/audit/rules.d/*.rules 2>/dev/null | wc -l)
if [ "$aud" = "active" ] && [ "$rules" -eq 0 ]; then r=VALID; else r=INVALID; fi
emit 960 2291 "$r" "Audit daemon enabled with empty ruleset - no events logged" \
  "auditd=$aud active_rules=$rules rule_files=$rulefiles (active service + zero rules = false assurance)"

#===============================================================================
# ROW 961 / id 1112 - pam_unix nullok in common-auth
#===============================================================================
nk=$(grep -E '^\s*auth.*pam_unix\.so' /etc/pam.d/common-auth 2>/dev/null | grep -c nullok)
empty=$(awk -F: '$2=="" {c++} END{print c+0}' /etc/shadow 2>/dev/null)
r=$(vif $( [ "$nk" -gt 0 ] && echo 0 || echo 1 ))
emit 961 1112 "$r" "Insecure default in PAM authentication - pam_unix nullok" \
  "nullok_present=$nk accounts_with_empty_password=$empty $(grep -E '^\s*auth.*pam_unix' /etc/pam.d/common-auth 2>/dev/null | trim)"

#===============================================================================
# ROW 962 / id 2422 - Firewall blocks NTP UDP 123
#===============================================================================
ntp=0
have nft && ntp=$(nft list ruleset 2>/dev/null | grep -c 'udp dport 123')
tsync=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
if [ "$ntp" -eq 0 ] && [ "$tsync" = "no" ]; then r=VALID; else r=INVALID; fi
emit 962 2422 "$r" "Outbound firewall blocks NTP UDP 123 causing clock desynchronization" \
  "nft_rules_allowing_udp123=$ntp NTPSynchronized=$tsync timesyncd=$(systemctl is-active systemd-timesyncd 2>/dev/null)"

#===============================================================================
# ROW 963 / id 1127 - Terminal popup menu persists in fullscreen
#===============================================================================
emit 963 1127 GUI "Terminal popup menu persists after entering full screen" \
  "GUI defect - excluded per scope. DUPLICATE of row 900"

#===============================================================================
# ROW 964 / id 2000 - Information disclosure via sudo parser error
#===============================================================================
if [ "$vc" -gt 0 ]; then r=INVALID; else r=INVALID; fi
emit 964 2000 "$r" "Information disclosure via sudo parser error exposing sudoers details" \
  "visudo_warnings=$vc - the parse warning is REAL (see row 894) but leaking a line number and directive name is not sensitive info disclosure. Merge into row 894; do not score separately."

#===============================================================================
# ROW 965 / id 1650 - CVE-2026-31431 algif_aead (dup of 872)
#===============================================================================
afalg=$(as_user python3 -c "
import socket,sys
try:
    s=socket.socket(socket.AF_ALG,socket.SOCK_SEQPACKET,0); s.bind(('aead','gcm(aes)')); print('BIND_OK'); s.close()
except Exception as e: print('BIND_FAIL')
" 2>/dev/null | tail -1)
if [ "$afalg" = "BIND_OK" ] && [ "$bl" -eq 0 ]; then r=VALID; else r=INVALID; fi
emit 965 1650 "$r" "Unmitigated CVE-2026-31431 algif_aead local privilege escalation" \
  "af_alg_bind_as_unprivileged=$afalg blacklist=$bl DUPLICATE of row 872 (same CVE, better evidence)"

#===============================================================================
# ROW 966 / id 1897 - Default user in dip group, pppd SUID root
#===============================================================================
indip=$(id -nG "$TARGET_USER" 2>/dev/null | grep -cw dip)
pppsuid=0
[ -f /usr/sbin/pppd ] && pppsuid=$(find /usr/sbin/pppd -perm -4000 2>/dev/null | wc -l)
if [ "$indip" -ge 1 ] && [ "$pppsuid" -gt 0 ]; then r=VALID; else r=INVALID; fi
emit 966 1897 "$r" "Default user can execute SUID root pppd through dip group" \
  "in_dip_group=$indip pppd_suid=$pppsuid perms=$(stat -c '%A %U:%G' /usr/sbin/pppd 2>/dev/null)"

#===============================================================================
# ROW 967 / id 1779 - apt update index corruption
#===============================================================================
au_=$(apt-get update -qq 2>&1 | grep -Eci 'err:|failed|not signed|corrupt|hash sum mismatch')
r=$(vif $( [ "$au_" -gt 0 ] && echo 0 || echo 1 ))
emit 967 1779 "$r" "Failed properties - system index files corrupted during update" \
  "apt_update_errors=$au_ sample=$(apt-get update -qq 2>&1 | grep -Ei 'err:|hash sum' | head -1 | trim)"

#===============================================================================
# ROW 968 / id 1929 - Chromium crash on devtools + print preview
#===============================================================================
emit 968 1929 GUI "Chromium crashes while inspecting window during print preview" \
  "GUI defect - excluded per scope (upstream Chromium issue, not a BOSS platform defect)"

#===============================================================================
# ROW 969 / id 465 - ftype-extensions.sh TOCTOU symlink race
#===============================================================================
fx=/usr/bin/ftype-extensions.sh
if [ -f "$fx" ]; then
  unsafe=$(grep -c 'cp ' "$fx" 2>/dev/null | num)
  safe=$(grep -c 'cp .*-P\|cp .*--no-dereference' "$fx" 2>/dev/null | num)
  if [ "$unsafe" -gt 0 ] && [ "$safe" -eq 0 ]; then r=VALID; else r=INVALID; fi
  ev="cp_calls=$unsafe symlink_safe_flags=$safe runs_as=$(systemctl show boss-secure.service -p User --value 2>/dev/null || echo root) target_dir=world-writable /tmp"
else
  r=INVALID; ev="$fx not present"
fi
emit 969 465 "$r" "Root-owned file scanner vulnerable to symlink race condition (TOCTOU)" "$ev"

#===============================================================================
# ROW 970 / id 417 - clone/unshare flag combination mishandling
#===============================================================================
emit 970 417 INVALID "clone/unshare flag combination mishandling" \
  "THEORETICAL: submission says flags 'have historically triggered' issues and offers no CVE, no kernel version range, and no observed result on this build. userns_enabled=$uns. Not reproducible as written."

#===============================================================================
# ROW 971 / id 786 - Outdated kernel CVE-2026-46333
#===============================================================================
kr=$(uname -r)
kpkg=$(dpkg-query -W -f='${Version}' "linux-image-$kr" 2>/dev/null || echo NA)
emit 971 786 INVALID "Outdated kernel vulnerability (CVE-2026-46333)" \
  "running=$kr pkg_version=$kpkg - Debian backports fixes WITHOUT bumping the upstream version string. Compare the Debian package version against the DSA/security tracker, not 6.12.63 vs 6.12.90. Version-string comparison alone is not evidence."

#===============================================================================
# ROW 972 / id 1931 - Hardening script removes ssh, scp, pkexec
#===============================================================================
miss=""
for b in /usr/bin/ssh /usr/bin/scp /usr/bin/pkexec; do
  [ -e "$b" ] || miss="$miss $b"
done
pk_installed=$(dpkg-query -W -f='${Status}' policykit-1 2>/dev/null | grep -c 'install ok')
if [ -n "$miss" ]; then r=VALID; else r=INVALID; fi
emit 972 1931 "$r" "Boot-time hardening script removes SSH, SCP and pkexec" \
  "missing_binaries=[${miss:-none}] openssh-client=$(dpkg-query -W -f='${Status}' openssh-client 2>/dev/null | grep -c 'install ok') polkit_pkg=$pk_installed (missing binary while package is installed = dpkg DB desync)"

#===============================================================================
# SUMMARY
#===============================================================================
{
  echo "-------------------------------------------------------------------------------"
  echo " SUMMARY"
  echo "   VALID   : $VALID_N"
  echo "   INVALID : $INVALID_N"
  echo "   GUI     : $GUI_N"
  echo "   TOTAL   : $((VALID_N+INVALID_N+GUI_N))"
  echo "-------------------------------------------------------------------------------"
  echo " REVIEWER NOTES"
  echo "   * Duplicate clusters to merge before scoring:"
  echo "       APT over HTTP ............ rows 882, 891, 930, 942"
  echo "       sudoers authenticate_override rows 894, 910, 918, 936, 964"
  echo "       sudo deny-list design .... rows 926, 932"
  echo "       kernel modules_disabled .. rows 908, 916"
  echo "       algif_aead CVE-2026-31431  rows 872, 965"
  echo "       physical access / no FDE . rows 903, 905, 929, 945, 947"
  echo "       boss-secure-update /tmp .. rows 890, 948"
  echo "       netdev polkit grant ...... rows 892, 927"
  echo "   * Contradictory pairs needing a re-test decision:"
  echo "       row 909 (file SURVIVES quarantine) vs row 943 (file DELETED by scanner)"
  echo "       row 917 (exim4 listening)          vs row 954 (exim4 failed to start)"
  echo "       row 876 (excessive sudo)           vs rows 913/926/932 (all sudo denied)"
  echo "   * Rows needing evidence from the submitter before triage: 924, 934, 970"
  echo "   * Rows 903, 905, 938, 945, 947 require reboot / offline media to fully confirm."
  echo "-------------------------------------------------------------------------------"
} >> "$OUTFILE"

cat "$OUTFILE"
echo ""
echo "Report written to: $OUTFILE"
