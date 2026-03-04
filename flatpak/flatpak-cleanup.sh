#!/bin/bash
# flatpak-cleanup.sh

LOCAL_REPO="/home/work/private/flatpak-shared-repo"
SERVER="gitlab.rm-rf.ch"
SERVER_REPO="/var/www/flatpak-repo"
GPG_KEY_ID="Tobi's Flatpak Repository (Flatpak Signing Key) <jahlives@gmx.ch>"
GPG_KEY_SHORT="FB762E35"

usage() {
    echo "Usage: $0 [--list] [--delete BRANCH] [--delete-pattern PATTERN] [--sync]"
    echo ""
    echo "  --list                    Zeigt alle Refs im lokalen Repo"
    echo "  --delete BRANCH           Löscht einen spezifischen Branch (z.B. 1.4.0-beta)"
    echo "  --delete-pattern PATTERN  Löscht alle Refs die auf Pattern matchen (z.B. 'beta|rc')"
    echo "  --sync                    Pusht lokales Repo auf Server nach dem Cleanup"
    echo ""
    echo "Beispiele:"
    echo "  $0 --list"
    echo "  $0 --delete 1.4.0-beta"
    echo "  $0 --delete-pattern 'beta|rc|b[0-9]'"
    echo "  $0 --delete-pattern 'beta|rc' --sync"
}

delete_branch() {
    local branch="$1"
    echo "🗑  Lösche Branch: $branch"

    # app/ und runtime/ (Debug) Refs löschen
    for ref in $(ostree --repo="$LOCAL_REPO" refs | grep "/$branch$"); do
        echo "   Lösche: $ref"
        ostree --repo="$LOCAL_REPO" refs --delete "$ref"
    done
}

sync_to_server() {
    echo "📤 Syncing zu Server (mit --delete)..."
    rsync -avz --delete "$LOCAL_REPO/objects/" "root@$SERVER:$SERVER_REPO/objects/"
    rsync -avz --delete "$LOCAL_REPO/refs/"    "root@$SERVER:$SERVER_REPO/refs/"
    rsync -avz           "$LOCAL_REPO/summary"* "root@$SERVER:$SERVER_REPO/"

    ssh "root@$SERVER" "
    ostree summary -u --repo=$SERVER_REPO --gpg-sign=$GPG_KEY_SHORT
    flatpak build-update-repo --gpg-sign=$GPG_KEY_SHORT $SERVER_REPO
    chown -R www-data:www-data $SERVER_REPO
    "
    echo "✅ Sync abgeschlossen"
}

DO_SYNC=false
ACTION=""
PARAM=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --list)
            ostree --repo="$LOCAL_REPO" refs | sort
            exit 0 ;;
        --delete)
            ACTION="delete"; PARAM="$2"; shift 2 ;;
        --delete-pattern)
            ACTION="pattern"; PARAM="$2"; shift 2 ;;
        --sync)
            DO_SYNC=true; shift ;;
        *) usage; exit 1 ;;
    esac
done

if [ "$ACTION" = "delete" ]; then
    delete_branch "$PARAM"
    ostree --repo="$LOCAL_REPO" prune --refs-only
    flatpak build-update-repo --gpg-sign="$GPG_KEY_ID" "$LOCAL_REPO"

elif [ "$ACTION" = "pattern" ]; then
    matches=$(ostree --repo="$LOCAL_REPO" refs | grep -E "$PARAM")
    if [ -z "$matches" ]; then
        echo "⚠  Keine Refs gefunden für Pattern: $PARAM"
        exit 0
    fi
    echo "Folgende Refs werden gelöscht:"
    echo "$matches"
    read -p "Fortfahren? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || exit 0

    echo "$matches" | xargs -I{} ostree --repo="$LOCAL_REPO" refs --delete {}
    ostree --repo="$LOCAL_REPO" prune --refs-only
    flatpak build-update-repo --gpg-sign="$GPG_KEY_ID" "$LOCAL_REPO"
fi

if [ "$DO_SYNC" = true ]; then
    sync_to_server
fi
