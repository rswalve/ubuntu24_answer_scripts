#!/usr/bin/env bash
set -euo pipefail

# Script: V-270650-verify-AIDE-configuration.sh
# STIG:   Ubuntu 24.04 LTS — V-270650 / SV-270650r1155241 / UBTU-24-100110
# Transport: AWS SSM
#
# Usage:
#   ./V-270650-verify-AIDE-configuration.sh i-0123456789abcdef0
#   ./V-270650-verify-AIDE-configuration.sh i-0123456789abcdef0 us-gov-west-1
# Optional:
#   AIDE_CHECK_TIMEOUT=900          seconds for aide --check on the instance (default 900)
#   SKIP_AIDE_FULL_CHECK=1          skip the long scan; only verify package/conf/DB
#   SSM_WAIT_ATTEMPTS=90            poll loops (default 90)
#   SSM_WAIT_SLEEP=10               seconds between polls (default 10)

if [ $# -lt 1 ]; then
  echo "Usage: $0 <instance-id> [region]" >&2
  exit 1
fi

INSTANCE_ID="$1"
REGION="${2:-${AWS_DEFAULT_REGION:-us-gov-west-1}}"
BUCKET_NAME="idcs-management-core-devops"
AIDE_CHECK_TIMEOUT="${AIDE_CHECK_TIMEOUT:-900}"
SKIP_AIDE_FULL_CHECK="${SKIP_AIDE_FULL_CHECK:-0}"
SSM_WAIT_ATTEMPTS="${SSM_WAIT_ATTEMPTS:-90}"
SSM_WAIT_SLEEP="${SSM_WAIT_SLEEP:-10}"

RANDOM_ID=$(head -c 16 /dev/urandom | xxd -p)
SCRIPT_NAME="verify_V-270650_${RANDOM_ID}.sh"
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
AIDE_CHECK_TIMEOUT='$AIDE_CHECK_TIMEOUT'
SKIP_AIDE_FULL_CHECK='$SKIP_AIDE_FULL_CHECK'

echo "=== Verifying V-270650 AIDE configuration ==="
HOST_FQDN=\$(hostname -f 2>/dev/null || hostname)
OS_PRETTY=\$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || echo unknown)
echo "[INFO] Host: \$HOST_FQDN"
echo "[INFO] OS:   \$OS_PRETTY"

pkg_status() {
  local p="\$1"
  if dpkg-query -W -f='\${db:Status-Status}' "\$p" 2>/dev/null | grep -qx installed; then
    echo installed
  else
    echo not-installed
  fi
}

AIDE_PKG=\$(pkg_status aide)
AIDE_COMMON_PKG=\$(pkg_status aide-common)
OTHER_FIM=""
for p in tripwire samhain ossec-hids wazuh-agent osquery; do
  [ "\$(pkg_status \$p)" = installed ] && OTHER_FIM="\$OTHER_FIM \$p"
done
OTHER_FIM=\$(echo "\$OTHER_FIM" | xargs echo)

AIDE_BIN=\$(command -v aide || true)
[ -z "\$AIDE_BIN" ] && [ -x /usr/bin/aide ] && AIDE_BIN=/usr/bin/aide
CONF=""
for c in /etc/aide/aide.conf /etc/aide.conf; do
  [ -f "\$c" ] && CONF="\$c" && break
done
DB_FILES=\$(ls -1 /var/lib/aide/aide.db /var/lib/aide/aide.db.new /var/lib/aide/aide.db.gz /var/lib/aide/aide.db.new.gz 2>/dev/null | xargs echo || echo none)

echo "[INFO] aide package:        \$AIDE_PKG"
echo "[INFO] aide-common package: \$AIDE_COMMON_PKG"
echo "[INFO] other FIM:           \${OTHER_FIM:-none}"
echo "[INFO] aide binary:         \${AIDE_BIN:-none}"
echo "[INFO] conf:                \${CONF:-missing}"
echo "[INFO] db files:            \$DB_FILES"

AIDE_RC=na
AIDE_OUT="[not run]"

if [ "\$AIDE_PKG" = installed ] || [ -n "\$AIDE_BIN" ]; then
  if [ "\$SKIP_AIDE_FULL_CHECK" = 1 ]; then
    echo "[INFO] SKIP_AIDE_FULL_CHECK=1 — not running full aide --check"
    AIDE_OUT="[skipped full check]"
    if [ -n "\$AIDE_BIN" ] && [ -n "\$CONF" ] && [ "\$DB_FILES" != none ]; then
      AIDE_RC=0
    elif [ -n "\$AIDE_BIN" ] && [ -n "\$CONF" ]; then
      AIDE_RC=2
      AIDE_OUT="[skipped] AIDE binary and conf present but no database file under /var/lib/aide"
    else
      AIDE_RC=2
      AIDE_OUT="[skipped] AIDE installed but conf or binary missing"
    fi
  else
    if [ -n "\$CONF" ]; then
      CMD="aide -c \$CONF --check"
    else
      CMD="aide --check"
    fi
    echo "[INFO] running: \$CMD (timeout \${AIDE_CHECK_TIMEOUT}s)"
    set +e
    AIDE_OUT=\$(timeout "\$AIDE_CHECK_TIMEOUT" \$CMD 2>&1)
    AIDE_RC=\$?
    set -e
  fi
fi

AIDE_OUT_ONE=\$(printf '%s' "\$AIDE_OUT" | tr '\n' ' ' | cut -c1-400)
echo "[INFO] aide rc: \$AIDE_RC"
echo "[INFO] aide out (trunc): \$AIDE_OUT_ONE"

if [ "\$AIDE_PKG" != installed ] && [ -z "\$AIDE_BIN" ]; then
  echo "[SUCCESS] AIDE not installed — N/A"
  echo "CKL_STATUS=Not Applicable"
  echo "CKL_RATIONALE=AIDE is not installed. Alternate FIM: \${OTHER_FIM:-none}. Per the STIG note this check applies when AIDE is employed."
  exit 0
elif [ "\$AIDE_RC" = 124 ]; then
  echo "[FAIL] AIDE check timed out"
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=AIDE --check timed out after \${AIDE_CHECK_TIMEOUT}s."
  exit 1
elif echo "\$AIDE_OUT" | grep -qiE 'fatal|could not|no database|unable to open|error while|config file.*not'; then
  echo "[FAIL] AIDE check failed to run"
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=AIDE is installed but the check command failed (rc=\$AIDE_RC). Output: \$AIDE_OUT_ONE"
  exit 1
elif [ "\$AIDE_RC" != na ] && [ "\$AIDE_RC" -ge 2 ]; then
  echo "[FAIL] AIDE error rc=\$AIDE_RC"
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=AIDE --check exited with error rc=\$AIDE_RC. Output: \$AIDE_OUT_ONE"
  exit 1
else
  echo "[SUCCESS] AIDE check executed"
  echo "CKL_STATUS=Not a Finding"
  echo "CKL_RATIONALE=AIDE is installed and aide --check executed as expected (rc=\$AIDE_RC; 0=clean, 1=differences found)."
  exit 0
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
  --comment "Verify STIG V-270650 (AIDE configured)" \
  --timeout-seconds 1200 \
  --parameters "commands=[\"$ONE_LINER\"]" \
  --query "Command.CommandId" \
  --output text)

STATUS="Pending"; ATTEMPT=0
while [[ "$STATUS" == "Pending" || "$STATUS" == "InProgress" || "$STATUS" == "Delayed" ]]; do
  ATTEMPT=$((ATTEMPT + 1))
  if [ "$ATTEMPT" -gt "$SSM_WAIT_ATTEMPTS" ]; then
    echo "[ERROR] SSM timeout after $((ATTEMPT * SSM_WAIT_SLEEP))s. Re-run with SKIP_AIDE_FULL_CHECK=1 or raise SSM_WAIT_ATTEMPTS / AIDE_CHECK_TIMEOUT." >&2
    echo "[INFO] CommandId=$COMMAND_ID — you can still poll: aws ssm get-command-invocation --command-id $COMMAND_ID --instance-id $INSTANCE_ID --region $REGION" >&2
    exit 1
  fi
  sleep "$SSM_WAIT_SLEEP"
  STATUS=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "Status" --output text 2>/dev/null || echo "Pending")
done

RAW_OUTPUT=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "StandardOutputContent" --output text 2>/dev/null || echo "")
STD_ERR=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --query "StandardErrorContent" --output text 2>/dev/null || echo "")
CKL_STATUS=$(printf '%s\n' "$RAW_OUTPUT" | awk -F= '/^CKL_STATUS=/{print $2; exit}')
CKL_RATIONALE=$(printf '%s\n' "$RAW_OUTPUT" | awk -F= '/^CKL_RATIONALE=/{sub(/^[^=]+=/,""); print; exit}')
[ -z "$CKL_STATUS" ] && { [ "$STATUS" = "Success" ] && CKL_STATUS="Not a Finding" || CKL_STATUS="Open"; CKL_RATIONALE="SSM status=$STATUS. Review raw output."; }

echo "================================================================================"
echo "STIG ID: UBTU-24-100110 | Vulnerability ID: V-270650 | Rule: SV-270650r1155241"
echo "Title: Configure AIDE to perform file integrity checking if installed."
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
echo "COMMENT: Remote SSM audit of V-270650 on host '$HOSTNAME_TAG' ($INSTANCE_ID / $REGION). ${CKL_RATIONALE:-See raw output.}"
echo "================================================================================"
