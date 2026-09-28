#!/usr/bin/env bash
set -euo pipefail
# Q12 V-274871 screensaver picture-uri not writable / blank
if [ $# -lt 1 ]; then echo "Usage: $0 <instance-id> [region]" >&2; exit 1; fi
INSTANCE_ID="$1"; REGION="${2:-${AWS_DEFAULT_REGION:-us-gov-west-1}}"
BUCKET_NAME="idcs-management-core-devops"
RANDOM_ID=$(head -c 16 /dev/urandom | xxd -p)
S3_KEY="tmp/verify_V-274871_${RANDOM_ID}.sh"
LOCAL_TMP_SCRIPT="/tmp/verify_V-274871_${RANDOM_ID}.sh"
cleanup(){ aws s3 rm "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null 2>&1 || true; rm -f "$LOCAL_TMP_SCRIPT" || true; }
trap cleanup EXIT
HOSTNAME_TAG=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --query "Reservations[0].Instances[0].Tags[?Key=='Hostname' || Key=='hostname' || Key=='HOSTNAME'].Value | [0]" --output text 2>/dev/null || echo "")
[ -z "$HOSTNAME_TAG" ] || [ "$HOSTNAME_TAG" = "None" ] || [ "$HOSTNAME_TAG" = "null" ] && HOSTNAME_TAG="[TAG NOT FOUND]"
cat << 'EOF' > "$LOCAL_TMP_SCRIPT"
#!/usr/bin/env bash
set -eo pipefail
echo "=== Verifying V-274871 screensaver conceal / picture-uri lock ==="
echo "[INFO] Host: $(hostname -f 2>/dev/null || hostname)"
GNOME_PKGS=$(dpkg-query -W -f='${Package} ${Status}\n' gnome-shell ubuntu-desktop gdm3 2>/dev/null | awk '/install ok installed/{print $1}' || true)
echo "[INFO] GNOME pkgs: ${GNOME_PKGS:-none}"
echo "[INFO] dconf profile: $([ -f /etc/dconf/profile/user ] && echo yes || echo no)"
if [ -z "$GNOME_PKGS" ] && [ ! -f /etc/dconf/profile/user ]; then
  echo "CKL_STATUS=Not Applicable"
  echo "CKL_RATIONALE=No graphical user interface (GNOME/dconf) is installed on this Ubuntu 24.04 EC2 instance. Requirement is Not Applicable per the STIG note."
  exit 0
fi
WR="[gsettings missing]"
if command -v gsettings >/dev/null 2>&1; then
  WR=$(gsettings writable org.gnome.desktop.screensaver picture-uri 2>&1 || true)
fi
echo "[INFO] gsettings writable picture-uri: $WR"
if echo "$WR" | grep -qx false; then
  echo "CKL_STATUS=Not a Finding"
  echo "CKL_RATIONALE=picture-uri is not writable ($WR)."
  exit 0
else
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=GUI present and picture-uri writable result is not false ($WR)."
  exit 1
fi
EOF
aws s3 cp "$LOCAL_TMP_SCRIPT" "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null
ONE_LINER="aws s3 cp s3://${BUCKET_NAME}/${S3_KEY} - --region ${REGION} | bash"
COMMAND_ID=$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE_ID" --document-name "AWS-RunShellScript" \
  --comment "Verify STIG V-274871" --parameters "commands=[\"$ONE_LINER\"]" --query "Command.CommandId" --output text)
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
echo "STIG Q12 | Vulnerability ID: V-274871 | Rule: SV-274871r1107302"
echo "Title: Conceal previously visible display via session lock image."
echo "Severity: CAT II"
echo "Execution Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "================================================================================"
echo ""; echo "--- COPY INTO 'FINDING DETAILS' ---"
echo "Target Hostname Tag: $HOSTNAME_TAG"; echo "Target Instance ID:  $INSTANCE_ID"
echo "AWS Region:          $REGION"; echo "SSM Command ID:      $COMMAND_ID"; echo "SSM Status:          $STATUS"
echo ""; echo "Remote SSM Verification Output:"; echo "$RAW_OUTPUT"
if [ -n "$STD_ERR" ] && [ "$STD_ERR" != "None" ]; then echo ""; echo "SSM StandardError:"; echo "$STD_ERR"; fi
echo ""; echo "--- COPY INTO 'COMMENTS' ---"
echo "STATUS: $CKL_STATUS"
echo "COMMENT: Remote SSM audit of V-274871 on host '$HOSTNAME_TAG' ($INSTANCE_ID / $REGION). ${CKL_RATIONALE:-See raw output.}"
echo "================================================================================"
