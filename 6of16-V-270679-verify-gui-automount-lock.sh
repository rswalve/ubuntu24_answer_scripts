#!/usr/bin/env bash
set -euo pipefail

# Script: V-270679-verify-gui-automount-lock.sh
# STIG:   Ubuntu 24.04 LTS — V-270679 / SV-270679r1107295 / Q6 of 16
# Transport: AWS SSM
# Usage: ./V-270679-verify-gui-automount-lock.sh <instance-id> [region]

if [ $# -lt 1 ]; then
  echo "Usage: $0 <instance-id> [region]" >&2
  exit 1
fi

INSTANCE_ID="$1"
REGION="${2:-${AWS_DEFAULT_REGION:-us-gov-west-1}}"
BUCKET_NAME="idcs-management-core-devops"
RANDOM_ID=$(head -c 16 /dev/urandom | xxd -p)
SCRIPT_NAME="verify_V-270679_${RANDOM_ID}.sh"
S3_KEY="tmp/${SCRIPT_NAME}"
LOCAL_TMP_SCRIPT="/tmp/${SCRIPT_NAME}"

cleanup() {
  echo "[INFO] Cleaning up staging artifacts..." >&2
  aws s3 rm "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null 2>&1 || true
  rm -f "$LOCAL_TMP_SCRIPT" || true
}
trap cleanup EXIT

HOSTNAME_TAG=$(aws ec2 describe-instances \
  --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --query "Reservations[0].Instances[0].Tags[?Key=='Hostname' || Key=='hostname' || Key=='HOSTNAME'].Value | [0]" \
  --output text 2>/dev/null || echo "")
if [ -z "$HOSTNAME_TAG" ] || [ "$HOSTNAME_TAG" = "None" ] || [ "$HOSTNAME_TAG" = "null" ]; then
  HOSTNAME_TAG="[TAG NOT FOUND]"
fi

cat << 'EOF' > "$LOCAL_TMP_SCRIPT"
#!/usr/bin/env bash
set -eo pipefail
echo "=== Verifying V-270679 GUI automount-open lock ==="
HOST_FQDN=$(hostname -f 2>/dev/null || hostname)
OS_PRETTY=$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || echo unknown)
echo "[INFO] Host: $HOST_FQDN"
echo "[INFO] OS:   $OS_PRETTY"

GNOME_PKGS=$(dpkg-query -W -f='${Package}\t${Status}\n' \
  gnome-shell ubuntu-desktop ubuntu-desktop-minimal gdm3 dconf-gsettings-backend \
  2>/dev/null | awk '/install ok installed/ {print $1}' || true)
DCONF_PROFILE="/etc/dconf/profile/user"
PROFILE_EXISTS=no
SYSTEM_DB="[missing]"
[ -f "$DCONF_PROFILE" ] && PROFILE_EXISTS=yes && SYSTEM_DB=$(grep system-db "$DCONF_PROFILE" 2>/dev/null | tr '\n' ' ' || echo "[no system-db line]")

echo "[INFO] GNOME/desktop pkgs: ${GNOME_PKGS:-none}"
echo "[INFO] dconf profile:      $PROFILE_EXISTS ($DCONF_PROFILE)"
echo "[INFO] system-db line:     $SYSTEM_DB"

LOCK_HITS="[none]"
if [ -d /etc/dconf/db ]; then
  LOCK_HITS=$(grep -R 'automount-open' /etc/dconf/db/*/locks/* 2>/dev/null | tr '\n' '|' || echo "[none]")
fi
echo "[INFO] automount-open locks: $LOCK_HITS"

GUI_PRESENT=no
if [ -n "$GNOME_PKGS" ] || [ "$PROFILE_EXISTS" = yes ]; then
  GUI_PRESENT=yes
fi
echo "[INFO] GUI present: $GUI_PRESENT"

if [ "$GUI_PRESENT" = no ]; then
  echo "[SUCCESS] No GUI — Not Applicable"
  echo "CKL_STATUS=Not Applicable"
  echo "CKL_RATIONALE=No graphical user interface (GNOME/dconf) is installed. /etc/dconf/profile/user does not exist. Requirement is Not Applicable per the STIG note."
  exit 0
fi

if echo "$LOCK_HITS" | grep -q 'automount-open'; then
  echo "[SUCCESS] automount-open is locked"
  echo "CKL_STATUS=Not a Finding"
  echo "CKL_RATIONALE=GUI is present and automount-open is locked under dconf: $LOCK_HITS"
  exit 0
else
  echo "[FAIL] automount-open lock missing"
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=GUI/dconf is present but grep for automount-open under /etc/dconf/db/*/locks did not return the required lock path."
  exit 1
fi
EOF

echo "[INFO] Staging payload to s3://${BUCKET_NAME}/${S3_KEY}..." >&2
aws s3 cp "$LOCAL_TMP_SCRIPT" "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null
echo "[INFO] SSM verify on $INSTANCE_ID ($HOSTNAME_TAG)..." >&2
ONE_LINER="aws s3 cp s3://${BUCKET_NAME}/${S3_KEY} - --region ${REGION} | bash"
COMMAND_ID=$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" --comment "Verify STIG V-270679" \
  --parameters "commands=[\"$ONE_LINER\"]" --query "Command.CommandId" --output text)

STATUS="Pending"; ATTEMPT=0
while [[ "$STATUS" == "Pending" || "$STATUS" == "InProgress" || "$STATUS" == "Delayed" ]]; do
  ATTEMPT=$((ATTEMPT + 1)); [ "$ATTEMPT" -gt 15 ] && echo "[ERROR] SSM timeout" >&2 && exit 1
  sleep 2
  STATUS=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "Status" --output text 2>/dev/null || echo "Pending")
done
RAW_OUTPUT=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "StandardOutputContent" --output text 2>/dev/null || echo "")
STD_ERR=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "StandardErrorContent" --output text 2>/dev/null || echo "")
CKL_STATUS=$(printf '%s\n' "$RAW_OUTPUT" | awk -F= '/^CKL_STATUS=/{print $2; exit}')
CKL_RATIONALE=$(printf '%s\n' "$RAW_OUTPUT" | awk -F= '/^CKL_RATIONALE=/{sub(/^[^=]+=/,""); print; exit}')
[ -z "$CKL_STATUS" ] && { [ "$STATUS" = "Success" ] && CKL_STATUS="Not a Finding" || CKL_STATUS="Open"; CKL_RATIONALE="SSM status=$STATUS."; }

echo "================================================================================"
echo "STIG ID: UBTU-24 (Q6) | Vulnerability ID: V-270679 | Rule: SV-270679r1107295"
echo "Title: Prevent user override of GUI automount disable."
echo "Severity: CAT II"
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
if [ -n "$STD_ERR" ] && [ "$STD_ERR" != "None" ]; then echo ""; echo "SSM StandardError:"; echo "$STD_ERR"; fi
echo ""
echo "--- COPY INTO 'COMMENTS' ---"
echo "STATUS: $CKL_STATUS"
echo "COMMENT: Remote SSM audit of V-270679 on host '$HOSTNAME_TAG' ($INSTANCE_ID / $REGION). ${CKL_RATIONALE:-See raw output.}"
echo "================================================================================"
