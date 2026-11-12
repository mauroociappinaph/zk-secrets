#!/bin/sh
# Removes the zks launcher, the installed app, the agent skill and the ~/AGENTS.md block.
# Keeps the audit log, the config and the Keychain tokens, and says so.
# sudo ./uninstall.sh --system removes the root-owned install (/usr/local/libexec/zks and
# /etc/paths.d/zks) instead; the skill and ~/AGENTS.md block are removed by a plain ./uninstall.sh.
set -eu

if [ "${1:-}" = "--system" ]; then
  [ "$(id -u)" = 0 ] || { printf 'uninstall.sh: --system needs root: run sudo ./uninstall.sh --system\n' >&2; exit 1; }
  if [ -d /usr/local/libexec/zks ]; then
    chmod -R u+w /usr/local/libexec/zks
    rm -rf /usr/local/libexec/zks
    printf 'removed /usr/local/libexec/zks\n'
  fi
  if [ -f /etc/paths.d/zks ]; then
    rm -f /etc/paths.d/zks
    printf 'removed /etc/paths.d/zks\n'
  fi
  exit 0
fi

USER_HOME="$(eval echo "~$(id -un)")"
BIN_LAUNCHER="$USER_HOME/.local/bin/zks"
LIBEXEC="$USER_HOME/.local/libexec/zks"
SKILL_DIR="$USER_HOME/.agents/skills/zks-secrets"
AGENTS="$USER_HOME/AGENTS.md"
CONFIG_DIR="$USER_HOME/.config/zks"
STATE_DIR="$USER_HOME/.local/state/zks"
BEGIN_MARK='<!-- zks:begin -->'
END_MARK='<!-- zks:end -->'

if [ -e "$BIN_LAUNCHER" ] || [ -L "$BIN_LAUNCHER" ]; then
  rm -f "$BIN_LAUNCHER"
  printf 'removed %s\n' "$BIN_LAUNCHER"
fi

if [ -d "$LIBEXEC" ]; then
  chmod -R u+w "$LIBEXEC"
  rm -rf "$LIBEXEC"
  printf 'removed %s\n' "$LIBEXEC"
fi

if [ -d "$SKILL_DIR" ]; then
  rm -rf "$SKILL_DIR"
  printf 'removed %s\n' "$SKILL_DIR"
fi

if [ -f "$AGENTS" ] && grep -qxF "$BEGIN_MARK" "$AGENTS"; then
  if grep -qxF "$END_MARK" "$AGENTS"; then
    TMP_FILE="$(mktemp)"
    trap 'rm -f "$TMP_FILE"' EXIT INT TERM
    awk -v begin="$BEGIN_MARK" -v end="$END_MARK" '
      !done && $0 == begin { skip = 1; next }
      skip && $0 == end { skip = 0; done = 1; next }
      skip { next }
      { print }
    ' "$AGENTS" >"$TMP_FILE"
    cat "$TMP_FILE" >"$AGENTS"
    printf 'removed the zks block from %s\n' "$AGENTS"
  else
    printf 'left %s untouched: %s has no matching %s\n' "$AGENTS" "$BEGIN_MARK" "$END_MARK" >&2
  fi
fi

cat <<EOF

Kept (delete by hand if you no longer need them):
  audit log:  $STATE_DIR/audit.db
  config:     $CONFIG_DIR (config.json, integrity.json)
  tokens:     macOS Keychain items with service "zks" (vercel, railway, supabase, sheets-hmac);
              remove one with: security delete-generic-password -s zks -a <provider>
  captures:   Keychain items that zks capture stored under other services (see zks audit list)
EOF
