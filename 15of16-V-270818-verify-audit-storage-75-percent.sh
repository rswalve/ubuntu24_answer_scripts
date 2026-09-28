#!/usr/bin/env bash
set -euo pipefail
# Q15 V-270818 space_left / space_left_action / action_mail_acct
if [ $# -lt 1 ]; then echo "Usage: $0 <instance-id> [region]" >&2; exit 1; fi
INSTANCE_ID="$1"; REGION="${2:-${AWS_DEFAULT_REGION:-us-gov-west-1}}"
BUCKET_NAME="idcs-management-core-devops"
RANDOM_ID=$(head -c 16 /dev/urandom | xxd -p)
S3_KEY="tmp/verify_V-270818_${RANDOM_ID}.sh"
LOCAL_TMP_SCRIPT="/tmp/verify_V-270818_${RANDOM_ID}.sh"
cleanup(){ aws s3 rm "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null 2>&1 || true; rm -f "$LOCAL_TMP_SCRIPT" || true; }
trap cleanup EXIT
HOSTNAME_TAG=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --query "Reservations[0].Instances[0].Tags[?Key=='Hostname' || Key=='hostname' || Key=='HOSTNAME'].Value | [0]" --output text 2>/dev/null || echo "")
[ -z "$HOSTNAME_TAG" ] || [ "$HOSTNAME_TAG" = "None" ] || [ "$HOSTNAME_TAG" = "null" ] && HOSTNAME_TAG="[TAG NOT FOUND]"
cat << 'EOF' > "$LOCAL_TMP_SCRIPT"
#!/usr/bin/env bash
set -eo pipefail
echo "=== Verifying V-270818 audit storage 75% notification ==="
echo "[INFO] Host: $(hostname -f 2>/dev/null || hostname)"
CONF=/etc/audit/auditd.conf
if [ ! -f "$CONF" ]; then
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=/etc/audit/auditd.conf is missing."
  exit 1
fi
SLA=$(grep -E '^[[:space:]]*space_left_action' "$CONF" | tail -n1 | awk '{print $NF}')
SL=$(grep -E '^[[:space:]]*space_left' "$CONF" | grep -v space_left_action | tail -n1 | awk '{print $NF}')
AMA=$(grep -E '^[[:space:]]*action_mail_acct' "$CONF" | tail -n1 | awk '{print $NF}')
LOGDIR=$(grep -E '^[[:space:]]*log_file' "$CONF" | tail -n1 | awk '{print $NF}')
[ -z "$LOGDIR" ] && LOGDIR=/var/log/audit/audit.log
LOGDIR=$(dirname "$LOGDIR")
echo "[INFO] space_left_action: ${SLA:-missing}"
echo "[INFO] space_left:        ${SL:-missing}"
echo "[INFO] action_mail_acct:  ${AMA:-missing}"
echo "[INFO] audit log dir:     $LOGDIR"
df -P "$LOGDIR" 2>/dev/null | tail -n1 | awk '{print "[INFO] filesystem",$1,"size",$2,"avail",$4}'

FAILS=""
[ -z "$SLA" ] && FAILS="$FAILS space_left_action-missing"
[ -z "$SL" ] && FAILS="$FAILS space_left-missing"
echo "$SL" | grep -qiE 'syslog|^$' && FAILS="$FAILS space_left-syslog-or-blank"

# If space_left is a percentage, require >= 25 (meaning notify by 75% full)
if echo "$SL" | grep -q '%'; then
  NUM=$(echo "$SL" | tr -dc '0-9')
  [ -n "$NUM" ] && [ "$NUM" -lt 25 ] && FAILS="$FAILS space_left-pct-below-25"
fi
# action email must name SA/ISSO when action is email
if echo "$SLA" | grep -qi email; then
  if [ -z "$AMA" ] || echo "$AMA" | grep -qiE 'root@localhost|^root$'; then
    FAILS="$FAILS action_mail_acct-not-SA-ISSO"
  fi
fi

if [ -z "$FAILS" ]; then
  echo "CKL_STATUS=Not a Finding"
  echo "CKL_RATIONALE=space_left_action=$SLA space_left=$SL action_mail_acct=${AMA:-n/a}. Values are present and not syslog/blank."
  exit 0
fi
echo "CKL_STATUS=Open"
echo "CKL_RATIONALE=Audit storage notification settings failed ($FAILS). space_left_action=$SLA space_left=$SL action_mail_acct=$AMA"
exit 1
EOF
aws s3 cp "$LOCAL_TMP_SCRIPT" "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null
ONE_LINER="aws s3 cp s3://${BUCKET_NAME}/${S3_KEY} - --region ${REGION} | bash"
COMMAND_ID=$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE_ID" --document-name "AWS-RunShellScript" \
  --comment "Verify STIG V-270818" --parameters "commands=[\"$ONE_LINER\"]" --query "Command.CommandId" --output text)
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
echo "STIG Q15 | Vulnerability ID: V-270818 | Rule: SV-270818r1066943"
echo "Title: Notify SA/ISSO when audit storage reaches 75 percent."
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
echo "COMMENT: Remote SSM audit of V-270818 on host '$HOSTNAME_TAG' ($INSTANCE_ID / $REGION). ${CKL_RATIONALE:-See raw output.}"
echo "================================================================================"
