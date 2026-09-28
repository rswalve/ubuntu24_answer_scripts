#!/usr/bin/env bash
set -euo pipefail

# Script: V-270735-verify-sssd-pki-cert-path.sh
# STIG:   Ubuntu 24.04 LTS — V-270735 / SV-270735r1066694 / Q9 of 16
# Transport: AWS SSM
# Usage: ./V-270735-verify-sssd-pki-cert-path.sh <instance-id> [region]

if [ $# -lt 1 ]; then
  echo "Usage: $0 <instance-id> [region]" >&2
  exit 1
fi

INSTANCE_ID="$1"
REGION="${2:-${AWS_DEFAULT_REGION:-us-gov-west-1}}"
BUCKET_NAME="idcs-management-core-devops"
RANDOM_ID=$(head -c 16 /dev/urandom | xxd -p)
SCRIPT_NAME="verify_V-270735_${RANDOM_ID}.sh"
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
echo "=== Verifying V-270735 SSSD PKI certificate path validation ==="
HOST_FQDN=$(hostname -f 2>/dev/null || hostname)
OS_PRETTY=$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || echo unknown)
echo "[INFO] Host: $HOST_FQDN"
echo "[INFO] OS:   $OS_PRETTY"

SSSD_PKG=not-installed
dpkg-query -W -f='${db:Status-Status}' sssd 2>/dev/null | grep -qx installed && SSSD_PKG=installed
CONF=""
for c in /etc/sssd/sssd.conf /etc/sssd.conf; do
  [ -f "$c" ] && CONF="$c" && break
done
echo "[INFO] sssd package: $SSSD_PKG"
echo "[INFO] sssd.conf:    ${CONF:-missing}"

if [ "$SSSD_PKG" != installed ] && [ -z "$CONF" ]; then
  echo "[SUCCESS] PKI/SSSD not employed — N/A"
  echo "CKL_STATUS=Not Applicable"
  echo "CKL_RATIONALE=sssd is not installed and no sssd.conf is present. PKI-based authentication via SSSD is not configured on this host."
  exit 0
fi

if [ -z "$CONF" ]; then
  echo "[FAIL] sssd installed but sssd.conf missing"
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=sssd is installed but /etc/sssd/sssd.conf was not found, so pam/certificate_verification settings cannot be verified."
  exit 1
fi

SSSD_SEC=$(awk 'BEGIN{p=0} /^\[sssd\]/{p=1;next} /^\[/{if(p==1) exit} p{print}' "$CONF")
PAM_SEC=$(awk 'BEGIN{p=0} /^\[pam\]/{p=1;next} /^\[/{if(p==1) exit} p{print}' "$CONF")
SERVICES=$(printf '%s\n' "$SSSD_SEC" | awk -F= '/^[[:space:]]*services/{gsub(/ /,"",$2); print $2}')
PAM_CERT=$(printf '%s\n' "$PAM_SEC" | awk -F= '/pam_cert_auth/{gsub(/ /,"",$2); print $2}')
CERT_VER=$(grep -E '^[[:space:]]*certificate_verification' "$CONF" 2>/dev/null | tail -n1 | awk -F= '{gsub(/^ +|/ +$/,"",$2); print $2}')

echo "[INFO] [sssd] services:          ${SERVICES:-missing}"
echo "[INFO] [pam] pam_cert_auth:      ${PAM_CERT:-missing}"
echo "[INFO] certificate_verification: ${CERT_VER:-missing}"

FAILS=""
echo "$SERVICES" | grep -qw pam || FAILS="$FAILS services-missing-pam"
echo "$PAM_CERT" | grep -qi '^true$' || FAILS="$FAILS pam_cert_auth-not-true"
# STIG: certificate_verification must include ca (ca, ca_cert, ocsp combinations accepted if ca present)
echo "$CERT_VER" | grep -qiE 'ca' || FAILS="$FAILS certificate_verification-missing-ca"

if [ -z "$FAILS" ]; then
  echo "[SUCCESS] SSSD PKI path validation configured"
  echo "CKL_STATUS=Not a Finding"
  echo "CKL_RATIONALE=sssd.conf has services including pam, pam_cert_auth=True, and certificate_verification includes ca ($CERT_VER)."
  exit 0
else
  echo "[FAIL] $FAILS"
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=SSSD PKI checks failed ($FAILS). services=$SERVICES pam_cert_auth=$PAM_CERT certificate_verification=$CERT_VER"
  exit 1
fi
EOF

echo "[INFO] Staging payload to s3://${BUCKET_NAME}/${S3_KEY}..." >&2
aws s3 cp "$LOCAL_TMP_SCRIPT" "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null
ONE_LINER="aws s3 cp s3://${BUCKET_NAME}/${S3_KEY} - --region ${REGION} | bash"
COMMAND_ID=$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" --comment "Verify STIG V-270735" \
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
echo "STIG ID: UBTU-24 (Q9) | Vulnerability ID: V-270735 | Rule: SV-270735r1066694"
echo "Title: SSSD must validate PKI certificates to a trust anchor."
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
echo "COMMENT: Remote SSM audit of V-270735 on host '$HOSTNAME_TAG' ($INSTANCE_ID / $REGION). ${CKL_RATIONALE:-See raw output.}"
echo "================================================================================"
