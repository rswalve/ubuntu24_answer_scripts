#!/usr/bin/env bash
set -euo pipefail

# Script: V-279938-verify-no-nfs-kernel-server-package-exists.sh
# STIG:   Ubuntu 24.04 LTS — V-279938 / SV-279938r1156367 / UBTU-24-100050
# Transport: AWS SSM
#
# Usage:
#   ./V-279938-verify-no-nfs-kernel-server-package-exists.sh i-0123456789abcdef0
#   ./V-279938-verify-no-nfs-kernel-server-package-exists.sh i-0123456789abcdef0 us-gov-west-1

if [ $# -lt 1 ]; then
  echo "Usage: $0 <instance-id> [region]" >&2
  exit 1
fi

INSTANCE_ID="$1"
REGION="${2:-${AWS_DEFAULT_REGION:-us-gov-west-1}}"
BUCKET_NAME="idcs-management-core-devops"

RANDOM_ID=$(head -c 16 /dev/urandom | xxd -p)
SCRIPT_NAME="verify_V-279938_${RANDOM_ID}.sh"
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

cat << 'EOF' > "$LOCAL_TMP_SCRIPT"
#!/usr/bin/env bash
set -eo pipefail

echo "=== Verifying V-279938 NFS packages not installed ==="
HOST_FQDN=$(hostname -f 2>/dev/null || hostname)
OS_PRETTY=$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || echo unknown)
echo "[INFO] Host: $HOST_FQDN"
echo "[INFO] OS:   $OS_PRETTY"

pkg_status() {
  local p="$1"
  if dpkg-query -W -f='${db:Status-Status}' "$p" 2>/dev/null | grep -qx installed; then
    echo "installed ($(dpkg-query -W -f='${Version}' "$p" 2>/dev/null))"
  else
    echo "not-installed"
  fi
}

NFS_COMMON_STATUS=$(pkg_status nfs-common)
NFS_SERVER_STATUS=$(pkg_status nfs-kernel-server)
DPKG_GREP=$(dpkg -l 2>/dev/null | grep -E 'nfs-common|nfs-kernel-server' || echo '[no matching dpkg -l rows]')
NFS_UNITS=$(systemctl list-units --type=service --all 2>/dev/null | grep -i nfs || echo '[no nfs systemd units]')

echo "[INFO] nfs-common:        $NFS_COMMON_STATUS"
echo "[INFO] nfs-kernel-server: $NFS_SERVER_STATUS"
echo "[INFO] dpkg -l matches:   $DPKG_GREP"
echo "[INFO] nfs units:         $NFS_UNITS"

INSTALLED_COUNT=0
echo "$NFS_COMMON_STATUS" | grep -q '^installed' && INSTALLED_COUNT=$((INSTALLED_COUNT+1))
echo "$NFS_SERVER_STATUS" | grep -q '^installed' && INSTALLED_COUNT=$((INSTALLED_COUNT+1))

if [ "$INSTALLED_COUNT" -eq 0 ]; then
  echo "[SUCCESS] Neither NFS package is installed"
  echo "CKL_STATUS=Not a Finding"
  echo "CKL_RATIONALE=Neither nfs-common nor nfs-kernel-server is installed."
  exit 0
else
  echo "[FAIL] NFS package(s) installed"
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=NFS package(s) are installed: nfs-common=${NFS_COMMON_STATUS}; nfs-kernel-server=${NFS_SERVER_STATUS}."
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
  --comment "Verify STIG V-279938 (no nfs-kernel-server)" \
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
echo "STIG ID: UBTU-24-100050 | Vulnerability ID: V-279938 | Rule: SV-279938r1156367"
echo "Title: Ubuntu 24.04 LTS must not have the nfs-kernel-server package installed."
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
echo "COMMENT: Remote SSM audit of V-279938 on host '$HOSTNAME_TAG' ($INSTANCE_ID / $REGION). ${CKL_RATIONALE:-See raw output.}"
echo "================================================================================"
