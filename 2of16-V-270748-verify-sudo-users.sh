#!/usr/bin/env bash
set -euo pipefail

# Script: V-270748-verify-sudo-users.sh
# STIG:   Ubuntu 24.04 LTS — V-270748 / SV-270748r1066733 / UBTU-24-600130
# Transport: AWS SSM (same pattern as v-284944)
#
# Usage:
#   ./V-270748-verify-sudo-users.sh i-0123456789abcdef0
#   ./V-270748-verify-sudo-users.sh i-0123456789abcdef0 us-gov-west-1
# Optional: EXPECTED_SUDO_USERS="ubuntu ssm-user"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <instance-id> [region]" >&2
  exit 1
fi

INSTANCE_ID="$1"
REGION="${2:-${AWS_DEFAULT_REGION:-us-gov-west-1}}"
BUCKET_NAME="idcs-management-core-devops"
EXPECTED_SUDO_USERS="${EXPECTED_SUDO_USERS:-ubuntu ssm-user}"

RANDOM_ID=$(head -c 16 /dev/urandom | xxd -p)
SCRIPT_NAME="verify_V-270748_${RANDOM_ID}.sh"
S3_KEY="tmp/${SCRIPT_NAME}"
LOCAL_TMP_SCRIPT="/tmp/${SCRIPT_NAME}"

cleanup() {
  echo "[INFO] Cleaning up staging artifacts..." >&2
  aws s3 rm "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null 2>&1 || true
  rm -f "$LOCAL_TMP_SCRIPT" || true
}
trap cleanup EXIT

HOSTNAME_TAG=$(aws ec2 describe-instances \
  --region "$REGION" \
  --instance-ids "$INSTANCE_ID" \
  --query "Reservations[0].Instances[0].Tags[?Key=='Hostname' || Key=='hostname' || Key=='HOSTNAME'].Value | [0]" \
  --output text 2>/dev/null || echo "")
if [ -z "$HOSTNAME_TAG" ] || [ "$HOSTNAME_TAG" = "None" ] || [ "$HOSTNAME_TAG" = "null" ]; then
  HOSTNAME_TAG="[TAG NOT FOUND]"
fi

cat << EOF > "$LOCAL_TMP_SCRIPT"
#!/usr/bin/env bash
set -eo pipefail
EXPECTED_SUDO_USERS='$EXPECTED_SUDO_USERS'

echo "=== Verifying V-270748 sudo group membership ==="
HOST_FQDN=\$(hostname -f 2>/dev/null || hostname)
OS_PRETTY=\$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || echo unknown)
echo "[INFO] Host: \$HOST_FQDN"
echo "[INFO] OS:   \$OS_PRETTY"

GROUP_LINE=\$(grep -E '^sudo:' /etc/group 2>/dev/null || echo '[sudo group line not found]')
GETENT_MEMBERS=\$(getent group sudo 2>/dev/null | awk -F: '{print \$4}' | tr ',' ' ' | xargs echo || true)
echo "[INFO] /etc/group: \$GROUP_LINE"
echo "[INFO] members:    \${GETENT_MEMBERS:-none}"
echo "[INFO] authorized: \$EXPECTED_SUDO_USERS"

UNEXPECTED=""
for u in \$GETENT_MEMBERS; do
  [ -z "\$u" ] && continue
  skip=0
  for e in \$EXPECTED_SUDO_USERS; do
    [ "\$u" = "\$e" ] && skip=1 && break
  done
  if [ "\$skip" -eq 0 ]; then
    case " \$UNEXPECTED " in
      *" \$u "*) ;;
      *) UNEXPECTED="\$UNEXPECTED \$u" ;;
    esac
  fi
done
UNEXPECTED=\$(echo "\$UNEXPECTED" | xargs echo)
echo "[INFO] unexpected: \${UNEXPECTED:-none}"

if [ ! -f /etc/group ] || ! grep -qE '^sudo:' /etc/group; then
  echo "[FAIL] Could not read sudo group"
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=Could not read the sudo group from /etc/group."
  exit 1
elif [ -z "\$UNEXPECTED" ]; then
  echo "[SUCCESS] sudo group limited to authorized admins"
  echo "CKL_STATUS=Not a Finding"
  echo "CKL_RATIONALE=sudo group members (\${GETENT_MEMBERS:-none}) are limited to authorized administrative account(s): \${EXPECTED_SUDO_USERS}."
  exit 0
else
  echo "[FAIL] unexpected sudo members: \$UNEXPECTED"
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=sudo group contains user(s) not in the authorized list (\${EXPECTED_SUDO_USERS}): \${UNEXPECTED}."
  exit 1
fi
EOF

echo "[INFO] Staging payload to s3://${BUCKET_NAME}/${S3_KEY}..." >&2
aws s3 cp "$LOCAL_TMP_SCRIPT" "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null

echo "[INFO] SSM verify on $INSTANCE_ID ($HOSTNAME_TAG)..." >&2
ONE_LINER="aws s3 cp s3://${BUCKET_NAME}/${S3_KEY} - --region ${REGION} | bash"

COMMAND_ID=$(aws ssm send-command \
  --region "$REGION" \
  --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --comment "Verify STIG V-270748 (sudo group members)" \
  --parameters "commands=[\"$ONE_LINER\"]" \
  --query "Command.CommandId" \
  --output text)

STATUS="Pending"; ATTEMPT=0
while [[ "$STATUS" == "Pending" || "$STATUS" == "InProgress" || "$STATUS" == "Delayed" ]]; do
  ATTEMPT=$((ATTEMPT + 1))
  [ "$ATTEMPT" -gt 15 ] && echo "[ERROR] SSM timeout" >&2 && exit 1
  sleep 2
  STATUS=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "Status" --output text 2>/dev/null || echo "Pending")
done

RAW_OUTPUT=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "StandardOutputContent" --output text 2>/dev/null || echo "")
STD_ERR=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "StandardErrorContent" --output text 2>/dev/null || echo "")
CKL_STATUS=$(printf '%s\n' "$RAW_OUTPUT" | awk -F= '/^CKL_STATUS=/{print $2; exit}')
CKL_RATIONALE=$(printf '%s\n' "$RAW_OUTPUT" | awk -F= '/^CKL_RATIONALE=/{sub(/^[^=]+=/,""); print; exit}')
[ -z "$CKL_STATUS" ] && { [ "$STATUS" = "Success" ] && CKL_STATUS="Not a Finding" || CKL_STATUS="Open"; CKL_RATIONALE="SSM status=$STATUS. Review raw output."; }

echo "================================================================================"
echo "STIG ID: UBTU-24-600130 | Vulnerability ID: V-270748 | Rule: SV-270748r1066733"
echo "Title: Only users who need access to security functions may be in the sudo group."
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
if [ -n "$STD_ERR" ] && [ "$STD_ERR" != "None" ]; then echo ""; echo "SSM StandardError:"; echo "$STD_ERR"; fi
echo ""
echo "--- COPY INTO 'COMMENTS' ---"
echo "STATUS: $CKL_STATUS"
echo "COMMENT: Remote SSM audit of V-270748 on host '$HOSTNAME_TAG' ($INSTANCE_ID / $REGION). ${CKL_RATIONALE:-See raw output.}"
echo "================================================================================"
