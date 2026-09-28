#!/usr/bin/env bash
set -euo pipefail
# Q11 V-270747 data at rest / crypttab (LUKS). EC2 EBS encryption is a separate infrastructure control.
if [ $# -lt 1 ]; then echo "Usage: $0 <instance-id> [region]" >&2; exit 1; fi
INSTANCE_ID="$1"; REGION="${2:-${AWS_DEFAULT_REGION:-us-gov-west-1}}"
BUCKET_NAME="idcs-management-core-devops"
RANDOM_ID=$(head -c 16 /dev/urandom | xxd -p)
S3_KEY="tmp/verify_V-270747_${RANDOM_ID}.sh"
LOCAL_TMP_SCRIPT="/tmp/verify_V-270747_${RANDOM_ID}.sh"
cleanup(){ aws s3 rm "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null 2>&1 || true; rm -f "$LOCAL_TMP_SCRIPT" || true; }
trap cleanup EXIT
HOSTNAME_TAG=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --query "Reservations[0].Instances[0].Tags[?Key=='Hostname' || Key=='hostname' || Key=='HOSTNAME'].Value | [0]" --output text 2>/dev/null || echo "")
[ -z "$HOSTNAME_TAG" ] || [ "$HOSTNAME_TAG" = "None" ] || [ "$HOSTNAME_TAG" = "null" ] && HOSTNAME_TAG="[TAG NOT FOUND]"
# Infrastructure-layer EBS evidence from the jump box (same idea as V-273994)
EBS_JSON=$(aws ec2 describe-volumes --region "$REGION" --filters "Name=attachment.instance-id,Values=$INSTANCE_ID" \
  --query "Volumes[*].{Device:Attachments[0].Device,VolumeId:VolumeId,Encrypted:Encrypted}" --output text 2>/dev/null || echo "")
UNENC=$(aws ec2 describe-volumes --region "$REGION" --filters "Name=attachment.instance-id,Values=$INSTANCE_ID" \
  --query "length(Volumes[?Encrypted==\`false\`])" --output text 2>/dev/null || echo "unknown")

cat << EOF > "$LOCAL_TMP_SCRIPT"
#!/usr/bin/env bash
set -eo pipefail
echo "=== Verifying V-270747 data-at-rest (crypttab / LUKS) ==="
echo "[INFO] Host: \$(hostname -f 2>/dev/null || hostname)"
echo "[INFO] fdisk -l (summary):"
fdisk -l 2>/dev/null | awk '/^Disk |^Device|Type/' | tr '\n' '|'
echo
echo "[INFO] lsblk:"
lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT,SIZE 2>/dev/null | tr '\n' '|'
echo
CRYPTTAB="[missing]"
[ -f /etc/crypttab ] && CRYPTTAB=\$(grep -vE '^[[:space:]]*(#|\$)' /etc/crypttab | tr '\n' '|' || echo "[empty]")
echo "[INFO] /etc/crypttab: \$CRYPTTAB"
LUKS=\$(lsblk -o TYPE,NAME 2>/dev/null | awk '\$1=="crypt"{print \$2}' | xargs echo || true)
echo "[INFO] crypt devices: \${LUKS:-none}"

# Persistent disks excluding typical boot/efi/bios
# Finding if crypttab has no real entries AND no mapped crypt devices
HAS_LUKS=no
[ -n "\$LUKS" ] && HAS_LUKS=yes
echo "\$CRYPTTAB" | grep -qvE '^\[(missing|empty)\]' && HAS_LUKS=yes

if [ "\$HAS_LUKS" = yes ]; then
  echo "[SUCCESS] LUKS/crypttab present"
  echo "CKL_STATUS=Not a Finding"
  echo "CKL_RATIONALE=Persistent volumes are represented in crypttab and/or mapped as crypt devices. crypttab=\$CRYPTTAB crypt=\${LUKS:-none}."
  exit 0
fi
echo "[INFO] No host-level LUKS. Assessor may accept EBS encryption as the DAR mechanism if documented."
echo "CKL_STATUS=Open"
echo "CKL_RATIONALE=No /etc/crypttab entries and no mapped crypt devices. STIG check is host LUKS. If EBS encryption-at-rest is the approved DAR control, document that as an accepted deviation / N/A per the STIG mission-requirement note."
exit 1
EOF

aws s3 cp "$LOCAL_TMP_SCRIPT" "s3://${BUCKET_NAME}/${S3_KEY}" --region "$REGION" >/dev/null
ONE_LINER="aws s3 cp s3://${BUCKET_NAME}/${S3_KEY} - --region ${REGION} | bash"
COMMAND_ID=$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE_ID" --document-name "AWS-RunShellScript" \
  --comment "Verify STIG V-270747" --parameters "commands=[\"$ONE_LINER\"]" --query "Command.CommandId" --output text)
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
echo "STIG Q11 | Vulnerability ID: V-270747 | Rule: SV-270747r1066730"
echo "Title: Employ cryptographic mechanisms for data at rest."
echo "Severity: CAT II"
echo "Execution Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "================================================================================"
echo ""; echo "--- COPY INTO 'FINDING DETAILS' ---"
echo "Target Hostname Tag: $HOSTNAME_TAG"; echo "Target Instance ID:  $INSTANCE_ID"
echo "AWS Region:          $REGION"; echo "SSM Command ID:      $COMMAND_ID"; echo "SSM Status:          $STATUS"
echo "EBS volume encryption (API):"; echo "${EBS_JSON:-[unavailable]}"
echo "Unencrypted EBS count: $UNENC"
echo ""; echo "Remote SSM Verification Output:"; echo "$RAW_OUTPUT"
if [ -n "$STD_ERR" ] && [ "$STD_ERR" != "None" ]; then echo ""; echo "SSM StandardError:"; echo "$STD_ERR"; fi
echo ""; echo "--- COPY INTO 'COMMENTS' ---"
echo "STATUS: $CKL_STATUS"
echo "COMMENT: Remote SSM audit of V-270747 on host '$HOSTNAME_TAG' ($INSTANCE_ID / $REGION). ${CKL_RATIONALE:-See raw output.} EBS unencrypted count=$UNENC."
echo "================================================================================"
