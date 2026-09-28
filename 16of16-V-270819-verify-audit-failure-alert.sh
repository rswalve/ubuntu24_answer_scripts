#!/usr/bin/env bash
set -euo pipefail
# Q16 V-270819 action_mail_acct for audit processing failure
if [ $# -lt 1 ]; then echo "Usage: $0 <instance-id> [region]" >&2; exit 1; fi
INSTANCE_ID="$1"; REGION="${2:-${AWS_DEFAULT_REGION:-us-gov-west-1}}"
BUCKET_NAME="idcs-management-core-devops"
RANDOM_ID=$(head -c 16 /dev/urandom | xxd -p)
S3_KEY="tmp/verify_V-270819_${RANDOM_ID}.sh"
LOCAL_TMP_SCRIPT="/tmp/verify_V-270819_${RANDOM_ID}.sh"
cleanup(){ aws s3 rm "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null 2>&1 || true; rm -f "$LOCAL_TMP_SCRIPT" || true; }
trap cleanup EXIT
HOSTNAME_TAG=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --query "Reservations[0].Instances[0].Tags[?Key=='Hostname' || Key=='hostname' || Key=='HOSTNAME'].Value | [0]" --output text 2>/dev/null || echo "")
[ -z "$HOSTNAME_TAG" ] || [ "$HOSTNAME_TAG" = "None" ] || [ "$HOSTNAME_TAG" = "null" ] && HOSTNAME_TAG="[TAG NOT FOUND]"
cat << 'EOF' > "$LOCAL_TMP_SCRIPT"
#!/usr/bin/env bash
set -eo pipefail
echo "=== Verifying V-270819 audit processing failure alert ==="
echo "[INFO] Host: $(hostname -f 2>/dev/null || hostname)"
CONF=/etc/audit/auditd.conf
if [ ! -f "$CONF" ]; then
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=/etc/audit/auditd.conf is missing."
  exit 1
fi
LINE=$(grep -E '^[[:space:]]*action_mail_acct' "$CONF" | tail -n1 || true)
AMA=$(printf '%s\n' "$LINE" | awk '{print $NF}')
echo "[INFO] action_mail_acct line: ${LINE:-missing}"
echo "[INFO] action_mail_acct value: ${AMA:-missing}"
DISK=$(grep -E '^[[:space:]]*disk_error_action|^[[:space:]]*disk_full_action|^[[:space:]]*admin_space_left_action' "$CONF" | tr '\n' '|' || true)
echo "[INFO] related actions: ${DISK:-none}"

if [ -z "$LINE" ] || [ -z "$AMA" ]; then
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=action_mail_acct is missing or commented out in auditd.conf."
  exit 1
fi
if echo "$AMA" | grep -qiE 'root@localhost|^root$'; then
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=action_mail_acct is $AMA which is not an SA/ISSO security-personnel mailbox."
  exit 1
fi
echo "CKL_STATUS=Not a Finding"
echo "CKL_RATIONALE=action_mail_acct is set to $AMA (not missing/commented). Confirm this address is the SA/ISSO mailbox for the site."
exit 0
EOF
aws s3 cp "$LOCAL_TMP_SCRIPT" "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null
ONE_LINER="aws s3 cp s3://${BUCKET_NAME}/${S3_KEY} - --region ${REGION} | bash"
COMMAND_ID=$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE_ID" --document-name "AWS-RunShellScript" \
  --comment "Verify STIG V-270819" --parameters "commands=[\"$ONE_LINER\"]" --query "Command.CommandId" --output text)
STATUS="Pending"; ATTEMPT=0
while [[ "$STATUS" == "Pending" || "$STATUS" == "InProgress" || "$STATUS" == "Delayed" ]]; do
  ATTEMPT=$((ATTEMPT+1)); [ "$ATTEMPT" -gt 15 ] && echo "[ERROR] SSM timeout" >&2 && exit 1; sleep 2
  STATUS=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "Status" --output text 2>/dev/null || echo Pending)
done
RAW_OUTPUT=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "StandardOutputContent" --output text 2>/dev/null || echo "")
STD_ERR=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "StandardErrorContent" --output text 2>/dev/null || echo "")
CKL_STATUS=$(printf '%s\n' "$RAW_OUTPUT" | awk -F= '/^CKL_STATUS=/{print $2; exit}')
CKL_RATIONALE=$(printf '%s\n' "$RAW_OUTPUT" | awk -F= '/^CKL_RATIONALE=/{sub(/^[^=]+=/,""); print; exit}')
[ -z "$CKL_STATUS" ] && { [ "$STATUS" = Success ] && CKL_STATUS="Not a Finding" || CKL_STATUS=Open; CKL_RATIONALE="SSM status=$STATUS."; }
echo "================================================================================"
echo "STIG Q16 | Vulnerability ID: V-270819 | Rule: SV-270819r1068390"
echo "Title: Alert SA/ISSO on audit processing failure."
echo "Severity: CAT III"
echo "Execution Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "================================================================================"
echo ""; echo "--- COPY INTO 'FINDING DETAILS' ---"
echo "Target Hostname Tag: $HOSTNAME_TAG"; echo "Target Instance ID:  $INSTANCE_ID"
echo "AWS Region:          $REGION"; echo "SSM Command ID:      $COMMAND_ID"; echo "SSM Status:          $STATUS"
echo ""; echo "Remote SSM Verification Output:"; echo "$RAW_OUTPUT"
if [ -n "$STD_ERR" ] && [ "$STD_ERR" != "None" ]; then echo ""; echo "SSM StandardError:"; echo "$STD_ERR"; fi
echo ""; echo "--- COPY INTO 'COMMENTS' ---"
echo "STATUS: $CKL_STATUS"
echo "COMMENT: Remote SSM audit of V-270819 on host '$HOSTNAME_TAG' ($INSTANCE_ID / $REGION). ${CKL_RATIONALE:-See raw output.}"
echo "================================================================================"
