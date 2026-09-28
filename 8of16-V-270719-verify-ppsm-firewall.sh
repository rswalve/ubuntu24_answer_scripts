#!/usr/bin/env bash
set -euo pipefail

# Script: V-270719-verify-ppsm-firewall.sh
# STIG:   Ubuntu 24.04 LTS — V-270719 / SV-270719r1067172 / Q8 of 16
# Transport: AWS SSM
# Note: PPSM CLSA comparison is a site/manual step. This script collects ufw/ss evidence.
# Usage: ./V-270719-verify-ppsm-firewall.sh <instance-id> [region]

if [ $# -lt 1 ]; then
  echo "Usage: $0 <instance-id> [region]" >&2
  exit 1
fi

INSTANCE_ID="$1"
REGION="${2:-${AWS_DEFAULT_REGION:-us-gov-west-1}}"
BUCKET_NAME="idcs-management-core-devops"
RANDOM_ID=$(head -c 16 /dev/urandom | xxd -p)
SCRIPT_NAME="verify_V-270719_${RANDOM_ID}.sh"
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
echo "=== Verifying V-270719 host firewall / PPSM evidence ==="
HOST_FQDN=$(hostname -f 2>/dev/null || hostname)
OS_PRETTY=$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || echo unknown)
echo "[INFO] Host: $HOST_FQDN"
echo "[INFO] OS:   $OS_PRETTY"

UFW_BIN=$(command -v ufw || true)
echo "[INFO] ufw binary: ${UFW_BIN:-none}"

UFW_STATUS="[ufw not installed]"
UFW_RAW="[ufw not installed]"
if [ -n "$UFW_BIN" ]; then
  UFW_STATUS=$(ufw status verbose 2>&1 | tr '\n' '|' || true)
  UFW_RAW=$(ufw show raw 2>&1 | tr '\n' '|' || true)
fi
echo "[INFO] ufw status verbose: $UFW_STATUS"
echo "[INFO] ufw show raw: $UFW_RAW"

LISTEN=$(ss -tulpnH 2>/dev/null | tr '\n' '|' || netstat -tulpn 2>/dev/null | tr '\n' '|' || echo "[cannot list listeners]")
echo "[INFO] listening sockets: $LISTEN"

ACTIVE_FW=no
echo "$UFW_STATUS" | grep -qiE 'Status: active' && ACTIVE_FW=yes
systemctl is-active nftables >/dev/null 2>&1 && ACTIVE_FW=yes
systemctl is-active iptables >/dev/null 2>&1 && ACTIVE_FW=yes
echo "[INFO] host firewall active indicator: $ACTIVE_FW"

if [ "$ACTIVE_FW" = no ]; then
  echo "[FAIL] no active host firewall collected"
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=No active ufw/nftables/iptables host firewall was detected. Cannot demonstrate PPSM port/protocol restriction on the host. Listening sockets: $LISTEN"
  exit 1
fi

echo "[INFO] Firewall present — PPSM CLSA comparison remains a manual SA step"
echo "CKL_STATUS=Not Reviewed"
echo "CKL_RATIONALE=Host firewall evidence collected (ufw/nft/iptables active). Assessor must compare allowed ports/protocols/services to the site PPSM CLSA. ufw status: $UFW_STATUS"
exit 0
EOF

echo "[INFO] Staging payload to s3://${BUCKET_NAME}/${S3_KEY}..." >&2
aws s3 cp "$LOCAL_TMP_SCRIPT" "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null
ONE_LINER="aws s3 cp s3://${BUCKET_NAME}/${S3_KEY} - --region ${REGION} | bash"
COMMAND_ID=$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" --comment "Verify STIG V-270719" \
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
[ -z "$CKL_STATUS" ] && { [ "$STATUS" = "Success" ] && CKL_STATUS="Not Reviewed" || CKL_STATUS="Open"; CKL_RATIONALE="SSM status=$STATUS."; }

echo "================================================================================"
echo "STIG ID: UBTU-24 (Q8) | Vulnerability ID: V-270719 | Rule: SV-270719r1067172"
echo "Title: Restrict ports/protocols/services per PPSM CAL."
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
echo "COMMENT: Remote SSM audit of V-270719 on host '$HOSTNAME_TAG' ($INSTANCE_ID / $REGION). ${CKL_RATIONALE:-See raw output.}"
echo "================================================================================"
