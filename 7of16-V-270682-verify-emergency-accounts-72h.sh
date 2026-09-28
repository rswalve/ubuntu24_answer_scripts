#!/usr/bin/env bash
set -euo pipefail

# Script: V-270682-verify-emergency-accounts-72h.sh
# STIG:   Ubuntu 24.04 LTS — V-270682 / SV-270682r1066535 / Q7 of 16
# Transport: AWS SSM
# Usage: ./V-270682-verify-emergency-accounts-72h.sh <instance-id> [region]
# Optional: EXPECTED_PERM_USERS="ubuntu ssm-user"  (not treated as emergency)

if [ $# -lt 1 ]; then
  echo "Usage: $0 <instance-id> [region]" >&2
  exit 1
fi

INSTANCE_ID="$1"
REGION="${2:-${AWS_DEFAULT_REGION:-us-gov-west-1}}"
BUCKET_NAME="idcs-management-core-devops"
EXPECTED_PERM_USERS="${EXPECTED_PERM_USERS:-ubuntu ssm-user}"
RANDOM_ID=$(head -c 16 /dev/urandom | xxd -p)
SCRIPT_NAME="verify_V-270682_${RANDOM_ID}.sh"
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

cat << EOF > "$LOCAL_TMP_SCRIPT"
#!/usr/bin/env bash
set -eo pipefail
EXPECTED_PERM_USERS='$EXPECTED_PERM_USERS'

echo "=== Verifying V-270682 emergency/temporary account 72-hour expiration ==="
HOST_FQDN=\$(hostname -f 2>/dev/null || hostname)
OS_PRETTY=\$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || echo unknown)
echo "[INFO] Host: \$HOST_FQDN"
echo "[INFO] OS:   \$OS_PRETTY"
echo "[INFO] Authorized permanent users: \$EXPECTED_PERM_USERS"

# Human/local accounts: UID >= 1000 plus known EC2 admins, exclude nobody/nfsnobody
CANDIDATES=\$(awk -F: '(\$3 >= 1000 && \$1 != "nobody" && \$1 != "nfsnobody") || \$1=="ubuntu" || \$1=="ssm-user" {print \$1}' /etc/passwd)
echo "[INFO] local/interactive accounts:"
echo "\$CANDIDATES"

BAD=""
REPORT=""
for u in \$CANDIDATES; do
  skip=0
  for e in \$EXPECTED_PERM_USERS; do
    [ "\$u" = "\$e" ] && skip=1 && break
  done
  CHAGE=\$(chage -l "\$u" 2>/dev/null | tr '\n' '|' || echo "[chage failed]")
  EXPIRES=\$(chage -l "\$u" 2>/dev/null | awk -F: '/Account expires/ {gsub(/^ +/,\"\",\$2); print \$2}')
  echo "[INFO] \$u account expires: \${EXPIRES:-unknown}"
  echo "[INFO] \$u chage: \$CHAGE"
  if [ "\$skip" -eq 1 ]; then
    REPORT="\$REPORT \$u=permanent;"
    continue
  fi
  # Any extra human account is treated as temporary/emergency and must expire within 72 hours
  if [ -z "\$EXPIRES" ] || echo "\$EXPIRES" | grep -qiE 'never|not set'; then
    BAD="\$BAD \$u(no-expiry)"
    continue
  fi
  EXP_EPOCH=\$(date -d "\$EXPIRES" +%s 2>/dev/null || echo "")
  NOW=\$(date +%s)
  if [ -z "\$EXP_EPOCH" ]; then
    BAD="\$BAD \$u(unparsed-expiry:\$EXPIRES)"
  else
    DELTA=\$(( (EXP_EPOCH - NOW) / 3600 ))
    echo "[INFO] \$u hours until expiry: \$DELTA"
    # Must already be set to expire; if remaining life > 72h from now, still a finding
    if [ "\$DELTA" -gt 72 ]; then
      BAD="\$BAD \$u(\${DELTA}h-remaining)"
    fi
  fi
done

if [ -z "\$BAD" ]; then
  echo "[SUCCESS] No noncompliant emergency accounts"
  echo "CKL_STATUS=Not a Finding"
  echo "CKL_RATIONALE=No temporary or emergency accounts requiring 72-hour expiration were found. Permanent accounts: \$EXPECTED_PERM_USERS. Other human accounts: none with missing/late expiration."
  exit 0
else
  echo "[FAIL] \$BAD"
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=Temporary/emergency-style account(s) lack a 72-hour expiration: \$BAD."
  exit 1
fi
EOF

echo "[INFO] Staging payload to s3://${BUCKET_NAME}/${S3_KEY}..." >&2
aws s3 cp "$LOCAL_TMP_SCRIPT" "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null
ONE_LINER="aws s3 cp s3://${BUCKET_NAME}/${S3_KEY} - --region ${REGION} | bash"
COMMAND_ID=$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" --comment "Verify STIG V-270682" \
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
echo "STIG ID: UBTU-24 (Q7) | Vulnerability ID: V-270682 | Rule: SV-270682r1066535"
echo "Title: Emergency accounts must expire within 72 hours."
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
echo "COMMENT: Remote SSM audit of V-270682 on host '$HOSTNAME_TAG' ($INSTANCE_ID / $REGION). ${CKL_RATIONALE:-See raw output.}"
echo "================================================================================"
