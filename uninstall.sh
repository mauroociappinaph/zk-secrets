#!/bin/sh
# Removes the zks launcher, the installed app, the agent skill and the ~/AGENTS.md block.
# Keeps the audit log, the config and the Keychain tokens, and says so.
set -eu

BIN_LAUNCHER="$HOME/.local/bin/zks"
LIBEXEC="$HOME/.local/libexec/zks"
SKILL_DIR="$HOME/.agents/skills/zks-secrets"
AGENTS="$HOME/AGENTS.md"
CONFIG_DIR="$HOME/.config/zks"
STATE_DIR="$HOME/.local/state/zks"
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
EOF
