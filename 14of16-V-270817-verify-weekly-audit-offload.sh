#!/usr/bin/env bash
set -euo pipefail
# Q14 V-270817 weekly audit-offload for standalone systems. Interconnected = N/A.
if [ $# -lt 1 ]; then echo "Usage: $0 <instance-id> [region]" >&2; exit 1; fi
INSTANCE_ID="$1"; REGION="${2:-${AWS_DEFAULT_REGION:-us-gov-west-1}}"
BUCKET_NAME="idcs-management-core-devops"
RANDOM_ID=$(head -c 16 /dev/urandom | xxd -p)
S3_KEY="tmp/verify_V-270817_${RANDOM_ID}.sh"
LOCAL_TMP_SCRIPT="/tmp/verify_V-270817_${RANDOM_ID}.sh"
cleanup(){ aws s3 rm "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null 2>&1 || true; rm -f "$LOCAL_TMP_SCRIPT" || true; }
trap cleanup EXIT
HOSTNAME_TAG=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --query "Reservations[0].Instances[0].Tags[?Key=='Hostname' || Key=='hostname' || Key=='HOSTNAME'].Value | [0]" --output text 2>/dev/null || echo "")
[ -z "$HOSTNAME_TAG" ] || [ "$HOSTNAME_TAG" = "None" ] || [ "$HOSTNAME_TAG" = "null" ] && HOSTNAME_TAG="[TAG NOT FOUND]"
cat << 'EOF' > "$LOCAL_TMP_SCRIPT"
#!/usr/bin/env bash
set -eo pipefail
echo "=== Verifying V-270817 weekly audit offload (standalone only) ==="
echo "[INFO] Host: $(hostname -f 2>/dev/null || hostname)"
WEEKLY=$(ls -1 /etc/cron.weekly 2>/dev/null | tr '\n' ' ' || echo "[no cron.weekly]")
echo "[INFO] /etc/cron.weekly: $WEEKLY"
OFFLOAD=""
[ -e /etc/cron.weekly/audit-offload ] && OFFLOAD=/etc/cron.weekly/audit-offload
[ -e /etc/cron.weekly/audit-offload.sh ] && OFFLOAD="$OFFLOAD /etc/cron.weekly/audit-offload.sh"
echo "[INFO] offload script: ${OFFLOAD:-none}"
# Interconnected heuristic: default route, SSM agent, or multiple NICs with addresses
INTERCONNECTED=no
ip route 2>/dev/null | grep -q default && INTERCONNECTED=yes
systemctl is-active amazon-ssm-agent >/dev/null 2>&1 && INTERCONNECTED=yes
echo "[INFO] interconnected heuristic: $INTERCONNECTED"

if [ "$INTERCONNECTED" = yes ] && [ -z "$OFFLOAD" ]; then
  echo "CKL_STATUS=Not Applicable"
  echo "CKL_RATIONALE=Host is interconnected (default route and/or SSM agent active). STIG note: if this is an interconnected system, this requirement is not applicable. No /etc/cron.weekly/audit-offload present."
  exit 0
fi
if [ -n "$OFFLOAD" ]; then
  HEAD=$(head -n 20 $OFFLOAD 2>/dev/null | tr '\n' '|' )
  echo "[INFO] script preview: $HEAD"
  echo "CKL_STATUS=Not a Finding"
  echo "CKL_RATIONALE=Weekly audit-offload script exists ($OFFLOAD)."
  exit 0
fi
echo "CKL_STATUS=Open"
echo "CKL_RATIONALE=No /etc/cron.weekly/audit-offload script found and host was not classified as interconnected. cron.weekly=$WEEKLY"
exit 1
EOF
aws s3 cp "$LOCAL_TMP_SCRIPT" "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null
ONE_LINER="aws s3 cp s3://${BUCKET_NAME}/${S3_KEY} - --region ${REGION} | bash"
COMMAND_ID=$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE_ID" --document-name "AWS-RunShellScript" \
  --comment "Verify STIG V-270817" --parameters "commands=[\"$ONE_LINER\"]" --query "Command.CommandId" --output text)
STATUS="Pending"; ATTEMPT=0
while [[ "$STATUS" == "Pending" || "$STATUS" == "InProgress" || "$STATUS" == "Delayed" ]]; do
  ATTEMPT=$((ATTEMPT+1)); [ "$ATTEMPT" -gt 15 ] && echo "[ERROR] SSM timeout" >&2 && exit 1; sleep 2
  STATUS=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "Status" --output text 2>/dev/null || echo Pending)
done
RAW_OUTPUT=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "StandardOutputContent" --output text 2>/dev/null || echo "")
STD_ERR=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "StandardErrorContent" --output text 2>/dev/null || echo "")
CKL_STATUS=$(printf '%s\n' "$RAW_OUTPUT" | awk -F= '/^CKL_STATUS=/{print $2; exit}')
CKL_RATIONALE=$(printf '%s\n' "$RAW_OUTPUT" | awk -F= '/^CKL_RATIONALE=/{sub(/^[^=]+=/,""); print; exit}')
[ -z "$CKL_STATUS" ] && { [ "$STATUS" = Success ] && CKL_STATUS="Not Applicable" || CKL_STATUS=Open; CKL_RATIONALE="SSM status=$STATUS."; }
echo "================================================================================"
echo "STIG Q14 | Vulnerability ID: V-270817 | Rule: SV-270817r1066940"
echo "Title: Weekly crontab to offload audit events on standalone systems."
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
echo "COMMENT: Remote SSM audit of V-270817 on host '$HOSTNAME_TAG' ($INSTANCE_ID / $REGION). ${CKL_RATIONALE:-See raw output.}"
echo "================================================================================"
