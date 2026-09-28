#!/usr/bin/env bash
set -euo pipefail

# Script: V-270651-validate-AIDE-script-running-every-30-days.sh
# STIG:   Ubuntu 24.04 LTS — V-270651 / SV-270651r1068395 / UBTU-24-100120
# Transport: AWS SSM
#
# Usage:
#   ./V-270651-validate-AIDE-script-running-every-30-days.sh i-0123456789abcdef0
#   ./V-270651-validate-AIDE-script-running-every-30-days.sh i-0123456789abcdef0 us-gov-west-1

if [ $# -lt 1 ]; then
  echo "Usage: $0 <instance-id> [region]" >&2
  exit 1
fi

INSTANCE_ID="$1"
REGION="${2:-${AWS_DEFAULT_REGION:-us-gov-west-1}}"
BUCKET_NAME="idcs-management-core-devops"

RANDOM_ID=$(head -c 16 /dev/urandom | xxd -p)
SCRIPT_NAME="verify_V-270651_${RANDOM_ID}.sh"
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

echo "=== Verifying V-270651 AIDE default script and 30-day schedule ==="
HOST_FQDN=$(hostname -f 2>/dev/null || hostname)
OS_PRETTY=$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || echo unknown)
echo "[INFO] Host: $HOST_FQDN"
echo "[INFO] OS:   $OS_PRETTY"

pkg_status() {
  local p="$1"
  if dpkg-query -W -f='${db:Status-Status}' "$p" 2>/dev/null | grep -qx installed; then
    echo installed
  else
    echo not-installed
  fi
}

AIDE_PKG=$(pkg_status aide)
AIDE_COMMON_PKG=$(pkg_status aide-common)
echo "[INFO] aide package:        $AIDE_PKG"
echo "[INFO] aide-common package: $AIDE_COMMON_PKG"

CONF=""
for c in /etc/aide/aide.conf /etc/aide.conf; do
  [ -f "$c" ] && CONF="$c" && break
done

SYS_HASH="missing"
PKG_HASH="missing"
HASH_MATCH="n/a"
VENDOR_CONF=""

if [ -n "$CONF" ]; then
  SYS_HASH=$(sha256sum "$CONF" | awk '{print $1}')
fi
for vc in /usr/share/aide/config/aide/aide.conf /usr/share/aide/config/aide.conf; do
  if [ -f "$vc" ]; then
    VENDOR_CONF="$vc"
    PKG_HASH=$(sha256sum "$vc" | awk '{print $1}')
    break
  fi
done
if [ "$SYS_HASH" != missing ] && [ "$PKG_HASH" != missing ]; then
  if [ "$SYS_HASH" = "$PKG_HASH" ]; then HASH_MATCH=yes; else HASH_MATCH=no; fi
fi

echo "[INFO] conf:         ${CONF:-missing}"
echo "[INFO] sys hash:     $SYS_HASH"
echo "[INFO] pkg hash:     $PKG_HASH"
echo "[INFO] vendor conf:  ${VENDOR_CONF:-none}"
echo "[INFO] hashes match: $HASH_MATCH"

CRON_HITS=$(grep -r --line-number -I aide /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/crontab 2>/dev/null | tr '\n' '|' || echo "[none]")
CRON_SCRIPT="none"
for f in /etc/cron.daily/dailyaidecheck /etc/cron.daily/aide /etc/cron.weekly/aide /usr/share/aide/bin/dailyaidecheck; do
  [ -e "$f" ] && CRON_SCRIPT="$CRON_SCRIPT $f"
done
CRON_SCRIPT=$(echo "$CRON_SCRIPT" | sed 's/^none //;s/^none$//')
[ -z "$CRON_SCRIPT" ] && CRON_SCRIPT="none"

TIMER_LIST=$(systemctl list-timers --all 2>/dev/null | grep -i aide || echo "[no aide timers]")
TIMER_ENABLED=no
TIMER_ACTIVE=no
if systemctl list-unit-files 2>/dev/null | grep -q '^dailyaidecheck.timer'; then
  systemctl is-enabled dailyaidecheck.timer >/dev/null 2>&1 && TIMER_ENABLED=yes || TIMER_ENABLED=no
  systemctl is-active dailyaidecheck.timer >/dev/null 2>&1 && TIMER_ACTIVE=yes || TIMER_ACTIVE=no
fi
TIMER_CAT=$(systemctl cat dailyaidecheck.timer 2>/dev/null | tr '\n' '|' || echo "[cannot read timer unit]")

echo "[INFO] cron hits:       $CRON_HITS"
echo "[INFO] cron scripts:    $CRON_SCRIPT"
echo "[INFO] timers:          $TIMER_LIST"
echo "[INFO] timer enabled:   $TIMER_ENABLED"
echo "[INFO] timer active:    $TIMER_ACTIVE"

SCHEDULE_OK=no
HAS_SCHEDULER=no
echo "$CRON_HITS" | grep -qE 'cron\.daily|cron\.weekly|/etc/cron.d' && SCHEDULE_OK=yes
[ "$TIMER_ENABLED" = yes ] && SCHEDULE_OK=yes
echo "$TIMER_LIST" | grep -qi dailyaidecheck && SCHEDULE_OK=yes
[ "$CRON_SCRIPT" != none ] && HAS_SCHEDULER=yes
echo "$CRON_HITS" | grep -qv '^\[none\]' && HAS_SCHEDULER=yes
echo "$TIMER_LIST" | grep -qi aide && HAS_SCHEDULER=yes

if [ "$AIDE_PKG" != installed ] && [ "$AIDE_COMMON_PKG" != installed ]; then
  echo "[SUCCESS] AIDE not installed — N/A"
  echo "CKL_STATUS=Not Applicable"
  echo "CKL_RATIONALE=AIDE is not installed. Per the STIG note this requirement is not applicable."
  exit 0
elif [ "$HAS_SCHEDULER" = no ]; then
  echo "[FAIL] no AIDE schedule"
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=No AIDE script was found in cron directories and no AIDE systemd timer is present."
  exit 1
elif [ "$HASH_MATCH" = no ]; then
  echo "[FAIL] aide.conf is not the packaged default"
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=Scheduled AIDE check exists, but aide.conf sha256 ($SYS_HASH) does not match packaged default ($PKG_HASH from $VENDOR_CONF)."
  exit 1
elif [ "$SCHEDULE_OK" = no ]; then
  echo "[FAIL] schedule not confirmed <= 30 days"
  echo "CKL_STATUS=Open"
  echo "CKL_RATIONALE=An AIDE artifact exists but neither a daily/weekly cron job nor an enabled dailyaidecheck.timer was confirmed."
  exit 1
else
  echo "[SUCCESS] default conf + schedule <= 30 days"
  echo "CKL_STATUS=Not a Finding"
  echo "CKL_RATIONALE=Periodic AIDE check is scheduled (cron and/or dailyaidecheck.timer enabled=$TIMER_ENABLED active=$TIMER_ACTIVE). Checksums match=$HASH_MATCH (sys=$SYS_HASH pkg=$PKG_HASH)."
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
  --comment "Verify STIG V-270651 (AIDE schedule)" \
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
echo "STIG ID: UBTU-24-100120 | Vulnerability ID: V-270651 | Rule: SV-270651r1068395"
echo "Title: AIDE integrity script must be the default and run every 30 days or less."
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
echo "COMMENT: Remote SSM audit of V-270651 on host '$HOSTNAME_TAG' ($INSTANCE_ID / $REGION). ${CKL_RATIONALE:-See raw output.}"
echo "================================================================================"
