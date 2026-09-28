#!/usr/bin/env bash
set -euo pipefail

# Script: V-270711-verify-the-x84-Ctrl-Alt-Delete-is-disabled.sh
# STIG:   Ubuntu 24.04 LTS — V-270711 / SV-270711r1184069 / UBTU-24-300025
# Transport: AWS SSM (same pattern as v-284944-verify-rsyslog-service-running.sh)
#
# Usage (Git Bash / jump server with AWS creds already configured):
#   ./V-270711-verify-the-x84-Ctrl-Alt-Delete-is-disabled.sh i-0123456789abcdef0
#   ./V-270711-verify-the-x84-Ctrl-Alt-Delete-is-disabled.sh i-0123456789abcdef0 us-gov-west-1

if [ $# -lt 1 ]; then
  echo "Usage: $0 <instance-id> [region]" >&2
  echo "Example: $0 i-0123456789abcdef0 us-gov-west-1" >&2
  exit 1
fi

INSTANCE_ID="$1"
REGION="${2:-${AWS_DEFAULT_REGION:-us-gov-west-1}}"
BUCKET_NAME="idcs-management-core-devops"

RANDOM_ID=$(head -c 16 /dev/urandom | xxd -p)
SCRIPT_NAME="verify_V-270711_${RANDOM_ID}.sh"
S3_KEY="tmp/${SCRIPT_NAME}"
LOCAL_TMP_SCRIPT="/tmp/${SCRIPT_NAME}"

cleanup() {
  echo "[INFO] Cleaning up staging artifacts..." >&2
  aws s3 rm "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null 2>&1 || true
  rm -f "$LOCAL_TMP_SCRIPT" || true
}
trap cleanup EXIT

if ! INSTANCE_DATA=$(aws ec2 describe-instances \
  --region "$REGION" \
  --instance-ids "$INSTANCE_ID" \
  --query "Reservations[0].Instances[0].{Tags:Tags}" \
  --output json 2>/dev/null); then
  echo "[ERROR] Failed to describe instance $INSTANCE_ID in region $REGION." >&2
  echo "[ERROR] Check AWS credentials (aws sts get-caller-identity) and region." >&2
  exit 1
fi

HOSTNAME_TAG=$(aws ec2 describe-instances \
  --region "$REGION" \
  --instance-ids "$INSTANCE_ID" \
  --query "Reservations[0].Instances[0].Tags[?Key=='Hostname' || Key=='hostname' || Key=='HOSTNAME'].Value | [0]" \
  --output text)

cat << 'EOF' > "$LOCAL_TMP_SCRIPT"
#!/usr/bin/env bash
set -eo pipefail

echo "=== Verifying V-270711 Ctrl-Alt-Delete graphical binding ==="

HOST_FQDN=$(hostname -f 2>/dev/null || hostname)
HOST_SHORT=$(hostname -s 2>/dev/null || hostname)
OS_PRETTY=$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || echo "unknown")
echo "[INFO] Host: $HOST_FQDN ($HOST_SHORT)"
echo "[INFO] OS:   $OS_PRETTY"

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

echo "[INFO] GUI present:          $GUI_PRESENT"
echo "[INFO] GNOME packages:       ${GNOME_PKGS:-none}"
echo "[INFO] dconf profile exists: $DCONF_PROFILE_EXISTS"
echo "[INFO] gsettings binary:     ${GSETTINGS_BIN:-none}"
echo "[INFO] media-keys schema:    $SCHEMA_PRESENT"
echo "[INFO] gsettings result:     $GSETTINGS_RAW"
echo "[INFO] gsettings exit code:  $GSETTINGS_RC"
echo "[INFO] Expected compliant:   @as []"

if [ "$GUI_PRESENT" = "no" ]; then
  echo "[SUCCESS] Not Applicable — no GNOME/desktop/dconf/media-keys schema on this host."
  echo "CKL_STATUS=Not Applicable"
  echo "CKL_RATIONALE=No GNOME/desktop packages, dconf user profile, or media-keys schema present. Rule applies only when a graphical user interface is installed."
  exit 0
elif [ "$GSETTINGS_RC" -ne 0 ]; then
  echo "[FAIL] GUI indicators present but gsettings could not read ${SCHEMA} ${KEY}."
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=GUI indicators present but gsettings could not read ${SCHEMA} ${KEY} (rc=${GSETTINGS_RC}). Key is missing or schema unavailable."
  exit 1
elif [ "$NORMALIZED" = "@as[]" ] || [ "$NORMALIZED" = "[]" ] || [ "$NORMALIZED" = "@as['']" ]; then
  echo "[SUCCESS] logout key is unbound."
  echo "CKL_STATUS=Not a Finding"
  echo "CKL_RATIONALE=gsettings reports logout is unbound (${GSETTINGS_RAW}). Ctrl-Alt-Delete graphical binding is disabled."
  exit 0
else
  echo "[FAIL] logout key is bound to an action."
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=logout key is bound to an action: ${GSETTINGS_RAW}. STIG requires an empty array (@as [])."
  exit 1
fi
EOF

echo "[INFO] Staging verification payload to s3://${BUCKET_NAME}/${S3_KEY}..." >&2
aws s3 cp "$LOCAL_TMP_SCRIPT" "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null

echo "[INFO] Streaming remote verification on $INSTANCE_ID ($HOSTNAME_TAG) via SSM..." >&2

ONE_LINER="aws s3 cp s3://${BUCKET_NAME}/${S3_KEY} - --region ${REGION} | bash"

COMMAND_ID=$(aws ssm send-command \
  --region "$REGION" \
  --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --comment "Verify STIG V-270711 (Ctrl-Alt-Delete GUI binding)" \
  --parameters "commands=[\"$ONE_LINER\"]" \
  --query "Command.CommandId" \
  --output text)

STATUS="Pending"
MAX_ATTEMPTS=15
ATTEMPT=0

while [[ "$STATUS" == "Pending" || "$STATUS" == "InProgress" || "$STATUS" == "Delayed" ]]; do
  ATTEMPT=$((ATTEMPT + 1))
  if [ "$ATTEMPT" -gt "$MAX_ATTEMPTS" ]; then
    echo "[ERROR] Timed out waiting for SSM command on $INSTANCE_ID." >&2
    exit 1
  fi
  sleep 2
  STATUS=$(aws ssm get-command-invocation \
    --region "$REGION" \
    --command-id "$COMMAND_ID" \
    --instance-id "$INSTANCE_ID" \
    --query "Status" \
    --output text 2>/dev/null || echo "Pending")
done

RAW_OUTPUT=$(aws ssm get-command-invocation \
  --region "$REGION" \
  --command-id "$COMMAND_ID" \
  --instance-id "$INSTANCE_ID" \
  --query "StandardOutputContent" \
  --output text 2>/dev/null || echo "")

STD_ERR=$(aws ssm get-command-invocation \
  --region "$REGION" \
  --command-id "$COMMAND_ID" \
  --instance-id "$INSTANCE_ID" \
  --query "StandardErrorContent" \
  --output text 2>/dev/null || echo "")

CKL_STATUS=$(printf '%s\n' "$RAW_OUTPUT" | awk -F= '/^CKL_STATUS=/{print $2; exit}')
CKL_RATIONALE=$(printf '%s\n' "$RAW_OUTPUT" | awk -F= '/^CKL_RATIONALE=/{sub(/^[^=]+=/,""); print; exit}')

if [ -z "$CKL_STATUS" ]; then
  if [ "$STATUS" = "Success" ]; then
    CKL_STATUS="Not a Finding"
    CKL_RATIONALE="SSM command succeeded but CKL markers were missing. Review raw output."
  else
    CKL_STATUS="Open"
    CKL_RATIONALE="Remote SSM verification failed on host '$HOSTNAME_TAG' ($INSTANCE_ID). SSM status=$STATUS."
  fi
fi

echo "================================================================================"
echo "STIG ID: UBTU-24-300025 | Vulnerability ID: V-270711 | Rule: SV-270711r1184069"
echo "Title: Ubuntu 24.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a GUI is installed."
echo "Severity: CAT I"
echo "Execution Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "================================================================================"
echo ""
echo "--- COPY INTO 'FINDING DETAILS' ---"
echo "Target Hostname Tag: $HOSTNAME_TAG"
echo "Target Instance ID:  $INSTANCE_ID"
echo "AWS Region:          $REGION"
echo "SSM Command ID:      $COMMAND_ID"
echo "SSM Status:          $STATUS"
echo ""
echo "Remote SSM Verification Output:"
echo "$RAW_OUTPUT"
if [ -n "$STD_ERR" ] && [ "$STD_ERR" != "None" ]; then
  echo ""
  echo "SSM StandardError:"
  echo "$STD_ERR"
fi
echo ""
echo "--- COPY INTO 'COMMENTS' ---"
echo "STATUS: $CKL_STATUS"
echo "COMMENT: Remote SSM audit of V-270711 on host '$HOSTNAME_TAG' ($INSTANCE_ID / $REGION). ${CKL_RATIONALE:-See raw output.}"
echo "================================================================================"