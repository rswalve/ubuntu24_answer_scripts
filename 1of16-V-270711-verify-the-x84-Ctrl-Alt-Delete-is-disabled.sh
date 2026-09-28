#!/usr/bin/env bash
set -euo pipefail

# Script: V-270711-verify-the-x84-Ctrl-Alt-Delete-is-disabled.sh
# STIG:   Ubuntu 24.04 LTS — V-270711 / SV-270711r1184069 / UBTU-24-300025
# Rule:   Disable the x86 Ctrl-Alt-Delete key sequence if a GUI is installed.
#
# Usage (run from jumpserver):
#   ./V-270711-verify-the-x84-Ctrl-Alt-Delete-is-disabled.sh ubuntu@10.0.1.25
#   ./V-270711-verify-the-x84-Ctrl-Alt-Delete-is-disabled.sh -i ~/.ssh/id_rsa ubuntu@i-0123.example
#
# Usage (run directly on the audited host):
#   ./V-270711-verify-the-x84-Ctrl-Alt-Delete-is-disabled.sh
#
# Extra args after the target are passed through to ssh (e.g. -i key, -p 22).

SSH_TARGET=""
SSH_OPTS=()

if [ $# -ge 1 ]; then
  # First non-option argument is treated as [user@]host
  while [ $# -gt 0 ]; do
    case "$1" in
      -*)
        SSH_OPTS+=("$1")
        if [ $# -ge 2 ] && [[ "$2" != -* ]]; then
          case "$1" in
            -i|-p|-o|-l|-F|-J|-b|-c|-D|-E|-e|-L|-R|-W|-w)
              SSH_OPTS+=("$2")
              shift
              ;;
          esac
        fi
        shift
        ;;
      *)
        SSH_TARGET="$1"
        shift
        SSH_OPTS+=("$@")
        break
        ;;
    esac
  done
fi

REMOTE_SCRIPT=$(cat <<'EOS'
set -euo pipefail

HOST_FQDN=$(hostname -f 2>/dev/null || hostname)
HOST_SHORT=$(hostname -s 2>/dev/null || hostname)
OS_PRETTY=$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || echo "unknown")

GSETTINGS_BIN=$(command -v gsettings || true)
GNOME_PKGS=$(dpkg-query -W -f='${Package}\t${Status}\n' \
  gnome-shell ubuntu-desktop ubuntu-desktop-minimal gdm3 \
  2>/dev/null | awk '/install ok installed/ {print $1}' || true)
DCONF_PROFILE_EXISTS="no"
[ -f /etc/dconf/profile/user ] && DCONF_PROFILE_EXISTS="yes"
SCHEMA="org.gnome.settings-daemon.plugins.media-keys"
KEY="logout"

GSETTINGS_RAW=""
GSETTINGS_RC=1
SCHEMA_PRESENT="no"

if [ -n "$GSETTINGS_BIN" ]; then
  if gsettings list-schemas 2>/dev/null | grep -qx "$SCHEMA"; then
    SCHEMA_PRESENT="yes"
    set +e
    GSETTINGS_RAW=$(gsettings get "$SCHEMA" "$KEY" 2>&1)
    GSETTINGS_RC=$?
    set -e
  else
    GSETTINGS_RAW="[schema not present] $SCHEMA"
    GSETTINGS_RC=2
  fi
else
  GSETTINGS_RAW="[gsettings binary not found]"
  GSETTINGS_RC=3
fi

NORMALIZED=$(printf '%s' "$GSETTINGS_RAW" | tr -d '[:space:]')

GUI_PRESENT="no"
if [ -n "$GNOME_PKGS" ] || [ "$DCONF_PROFILE_EXISTS" = "yes" ] || [ "$SCHEMA_PRESENT" = "yes" ]; then
  GUI_PRESENT="yes"
fi

STATUS=""
RATIONALE=""

if [ "$GUI_PRESENT" = "no" ]; then
  STATUS="Not Applicable"
  RATIONALE="No GNOME/desktop packages, dconf user profile, or media-keys schema present. Rule applies only when a graphical user interface is installed."
elif [ "$GSETTINGS_RC" -ne 0 ]; then
  STATUS="Open"
  RATIONALE="GUI indicators present but gsettings could not read ${SCHEMA} ${KEY} (rc=${GSETTINGS_RC}). Key is missing or schema unavailable."
elif [ "$NORMALIZED" = "@as[]" ] || [ "$NORMALIZED" = "[]" ] || [ "$NORMALIZED" = "@as['']" ]; then
  STATUS="Not a Finding"
  RATIONALE="gsettings reports logout is unbound (${GSETTINGS_RAW}). Ctrl-Alt-Delete graphical binding is disabled."
else
  STATUS="Open"
  RATIONALE="logout key is bound to an action: ${GSETTINGS_RAW}. STIG requires an empty array (@as [])."
fi

printf 'HOST_FQDN=%s\n' "$HOST_FQDN"
printf 'HOST_SHORT=%s\n' "$HOST_SHORT"
printf 'OS_PRETTY=%s\n' "$OS_PRETTY"
printf 'GUI_PRESENT=%s\n' "$GUI_PRESENT"
printf 'GNOME_PKGS=%s\n' "${GNOME_PKGS:-none}"
printf 'DCONF_PROFILE_EXISTS=%s\n' "$DCONF_PROFILE_EXISTS"
printf 'GSETTINGS_BIN=%s\n' "${GSETTINGS_BIN:-none}"
printf 'SCHEMA_PRESENT=%s\n' "$SCHEMA_PRESENT"
printf 'GSETTINGS_RAW=%s\n' "$GSETTINGS_RAW"
printf 'GSETTINGS_RC=%s\n' "$GSETTINGS_RC"
printf 'STATUS=%s\n' "$STATUS"
printf 'RATIONALE=%s\n' "$RATIONALE"
EOS
)

run_remote() {
  if [ -n "$SSH_TARGET" ]; then
    ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
      "${SSH_OPTS[@]}" "$SSH_TARGET" "bash -s" <<<"$REMOTE_SCRIPT"
  else
    bash -c "$REMOTE_SCRIPT"
  fi
}

if ! RESULT=$(run_remote); then
  echo "[ERROR] Failed to execute check on ${SSH_TARGET:-localhost}. Check SSH credentials/connectivity or local privileges." >&2
  exit 1
fi

get_field() {
  printf '%s\n' "$RESULT" | awk -F= -v k="$1" '$1==k {sub(/^[^=]+=/,""); print; exit}'
}

HOST_FQDN=$(get_field HOST_FQDN)
HOST_SHORT=$(get_field HOST_SHORT)
OS_PRETTY=$(get_field OS_PRETTY)
GUI_PRESENT=$(get_field GUI_PRESENT)
GNOME_PKGS=$(get_field GNOME_PKGS)
DCONF_PROFILE_EXISTS=$(get_field DCONF_PROFILE_EXISTS)
GSETTINGS_BIN=$(get_field GSETTINGS_BIN)
SCHEMA_PRESENT=$(get_field SCHEMA_PRESENT)
GSETTINGS_RAW=$(get_field GSETTINGS_RAW)
GSETTINGS_RC=$(get_field GSETTINGS_RC)
STATUS=$(get_field STATUS)
RATIONALE=$(get_field RATIONALE)

TARGET_LABEL="${SSH_TARGET:-localhost}"

echo "================================================================================"
echo "STIG ID: UBTU-24-300025 | Vulnerability ID: V-270711 | Rule: SV-270711r1184069"
echo "Title: Ubuntu 24.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a GUI is installed."
echo "Severity: CAT I"
echo "Execution Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "================================================================================"
echo ""
echo "--- COPY INTO 'FINDING DETAILS' ---"
echo "Target (SSH/local):     $TARGET_LABEL"
echo "Hostname (FQDN):        $HOST_FQDN"
echo "Hostname (short):       $HOST_SHORT"
echo "OS:                     $OS_PRETTY"
echo "GUI present:            $GUI_PRESENT"
echo "Installed GNOME pkgs:   $GNOME_PKGS"
echo "dconf profile exists:   $DCONF_PROFILE_EXISTS"
echo "gsettings binary:       $GSETTINGS_BIN"
echo "media-keys schema:      $SCHEMA_PRESENT"
echo "gsettings command:      gsettings get org.gnome.settings-daemon.plugins.media-keys logout"
echo "gsettings result:       $GSETTINGS_RAW"
echo "gsettings exit code:    $GSETTINGS_RC"
echo "Expected compliant:     @as []"
echo ""
echo "--- COPY INTO 'COMMENTS' ---"
echo "STATUS: $STATUS"
echo "COMMENT: Remote/local audit of V-270711 on host '$HOST_FQDN' ($TARGET_LABEL). $RATIONALE"
echo "================================================================================"