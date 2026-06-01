#!/bin/bash
# Upload a freshly built goloom-wg-server-linux binary to a remote host,
# atomically swap it into place, restart the systemd unit, and prune
# old backups so /opt doesn't fill up.
#
# Usage:
#   ./deploy/upload.sh user@host [--unit goloom-wg-server] [--dir /opt/goloom] [--keep 2]
#
# Defaults target a standard install (--dir /opt/goloom, --unit
# goloom-wg-server). Override them if you deploy to a different path or
# run several instances on one host.
#
# Why a script: a manual deploy is a 4-step copy/paste over SSH (scp
# .new, cp -p backup, mv, restart) plus manual `rm` of old .bak.* files
# when /opt fills up. This automates the atomic swap and prunes old
# backups, keeping the last $KEEP for rollback.

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 user@host [--unit NAME] [--dir PATH] [--keep N]" >&2
    exit 1
fi

REMOTE="$1"
shift

UNIT="goloom-wg-server"
DIR="/opt/goloom"
KEEP=2
BINARY_LOCAL="goloom-wg-server-linux"
BINARY_REMOTE="goloom-wg-server"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --unit)   UNIT="$2";   shift 2 ;;
        --dir)    DIR="$2";    shift 2 ;;
        --keep)   KEEP="$2";   shift 2 ;;
        --binary) BINARY_LOCAL="$2"; shift 2 ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

if [[ ! -f "$BINARY_LOCAL" ]]; then
    echo "ERROR: $BINARY_LOCAL not found in cwd." >&2
    echo "Build it first:" >&2
    echo "  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags=\"-s -w\" -o $BINARY_LOCAL ./cmd/goloom-wg-server" >&2
    exit 1
fi

LOCAL_HASH=$(sha256sum "$BINARY_LOCAL" | awk '{print $1}')
SIZE=$(stat -c%s "$BINARY_LOCAL" 2>/dev/null || wc -c < "$BINARY_LOCAL")
echo "→ uploading $BINARY_LOCAL ($SIZE bytes, sha256=${LOCAL_HASH:0:16}…) to $REMOTE:$DIR/$BINARY_REMOTE.new"
scp -o ConnectTimeout=15 "$BINARY_LOCAL" "$REMOTE:$DIR/$BINARY_REMOTE.new"

echo "→ verifying checksum on remote"
REMOTE_HASH=$(ssh -o ConnectTimeout=10 "$REMOTE" "sha256sum $DIR/$BINARY_REMOTE.new | awk '{print \$1}'")
if [[ "$LOCAL_HASH" != "$REMOTE_HASH" ]]; then
    echo "ERROR: checksum mismatch — upload corrupted" >&2
    echo "  local:  $LOCAL_HASH" >&2
    echo "  remote: $REMOTE_HASH" >&2
    exit 1
fi

echo "→ atomic swap + restart + retention (keep last $KEEP backups)"
ssh -o ConnectTimeout=10 "$REMOTE" "
    set -e
    ts=\$(date +%Y%m%d-%H%M%S)
    cp -p $DIR/$BINARY_REMOTE $DIR/$BINARY_REMOTE.bak.\$ts
    chmod +x $DIR/$BINARY_REMOTE.new
    mv $DIR/$BINARY_REMOTE.new $DIR/$BINARY_REMOTE
    systemctl restart $UNIT
    sleep 3
    systemctl is-active $UNIT

    # Retention: keep the $KEEP most recent .bak.* files, drop the rest.
    # ls -1t prints newest-first; tail +N skips the first N-1 entries so
    # +(KEEP+1) yields everything past the cutoff.
    ls -1t $DIR/$BINARY_REMOTE.bak.* 2>/dev/null | tail -n +\$((${KEEP}+1)) | xargs -r rm -v
"

echo "✓ deploy complete"
