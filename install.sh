#!/bin/sh
# Installs zks for the current macOS user:
#   ~/.local/libexec/zks/<version>/   read-only app (dist, bin, production node_modules)
#   ~/.local/bin/zks                  launcher with the absolute install path baked in
#   ~/.config/zks/integrity.json      digest of the install, checked by `zks doctor`
#   ~/.agents/skills/zks-secrets/     agent skill
#   ~/AGENTS.md                       global rule between <!-- zks:begin --> and <!-- zks:end -->
# Run from the repository root. It never reads, prints or stores a secret value.
set -eu
umask 077

die() {
  printf 'install.sh: %s\n' "$1" >&2
  exit 1
}

[ "$(uname -s)" = "Darwin" ] || die "zks needs macOS (native approval dialog and Keychain)"
[ -f package.json ] && [ -f src/cli.ts ] && [ -f skill/SKILL.md ] || die "run ./install.sh from the zk-secrets repository root"
command -v node >/dev/null 2>&1 || die "node >= 22.18 is required and was not found on PATH"
command -v npm >/dev/null 2>&1 || die "npm is required and was not found on PATH"
unset NODE_OPTIONS
node -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 18) ? 0 : 1)' ||
  die "node >= 22.18 is required (found $(node --version))"

REPO="$(pwd -P)"
VERSION="$(node -p 'require("./package.json").version')"
LIBEXEC="$HOME/.local/libexec/zks"
DEST="$LIBEXEC/$VERSION"
BIN_DIR="$HOME/.local/bin"
LAUNCHER="$BIN_DIR/zks"
CONFIG_DIR="$HOME/.config/zks"
INTEGRITY="$CONFIG_DIR/integrity.json"
SKILL_DIR="$HOME/.agents/skills/zks-secrets"
AGENTS="$HOME/AGENTS.md"
BEGIN_MARK='<!-- zks:begin -->'
END_MARK='<!-- zks:end -->'

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

printf '==> Checking and building zks %s\n' "$VERSION"
npm ci
npm run check
npm run build
[ -f dist/cli.js ] || die "build did not produce dist/cli.js"

printf '==> Installing into %s\n' "$DEST"
if [ -e "$DEST" ]; then
  chmod -R u+w "$DEST"
  rm -rf "$DEST"
fi
mkdir -p "$DEST"
cp -R dist bin package.json package-lock.json "$DEST/"
(cd "$DEST" && npm ci --omit=dev --ignore-scripts)
chmod 755 "$DEST/bin/zks"
DEST="$(cd "$DEST" && pwd -P)"

printf '==> Writing launcher %s\n' "$LAUNCHER"
mkdir -p "$BIN_DIR"
if [ -e "$LAUNCHER" ] || [ -L "$LAUNCHER" ]; then
  chmod u+w "$LAUNCHER" 2>/dev/null || true
  rm -f "$LAUNCHER"
fi
cat >"$LAUNCHER" <<EOF
#!/bin/sh
# zks launcher written by install.sh. Do not edit: reinstall with ./install.sh instead.
exec "$DEST/bin/zks" "\$@"
EOF
chmod 555 "$LAUNCHER"

chmod -R a-w "$DEST"

printf '==> Recording integrity manifest %s\n' "$INTEGRITY"
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"
if [ -e "$INTEGRITY" ]; then chmod u+w "$INTEGRITY"; fi
ZKS_DEST="$DEST" ZKS_VERSION="$VERSION" ZKS_INTEGRITY="$INTEGRITY" node --input-type=module -e '
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
const root = process.env.ZKS_DEST;
const { digestTree } = await import(pathToFileURL(join(root, "dist/platform/integrity.js")).href);
const { digest, files } = digestTree(root);
const manifest = { version: process.env.ZKS_VERSION, root, digest, files };
writeFileSync(process.env.ZKS_INTEGRITY, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
'
chmod 600 "$INTEGRITY"

printf '==> Installing skill %s\n' "$SKILL_DIR"
mkdir -p "$SKILL_DIR"
cp "$REPO/skill/SKILL.md" "$SKILL_DIR/SKILL.md"
chmod 644 "$SKILL_DIR/SKILL.md"

printf '==> Updating global agent rule in %s\n' "$AGENTS"
BLOCK="$TMP_DIR/block.md"
cat >"$BLOCK" <<'EOF'
<!-- zks:begin -->
## Secrets and environment variables

- Never ask for, read, print, or store secret values: no `.env` files, tokens, `vercel env pull`, `aws ... --with-decryption`, `op read`, or provider dashboards.
- To set secrets or env vars on Vercel, AWS SSM/Secrets Manager, GitHub Actions, Railway or Supabase, use the `zks-secrets` skill and the `zks` CLI only.
- If a user pastes a secret into the chat, do not use it and tell them to rotate it.
- zks writes need the human's approval in a native dialog; never try to bypass or automate that dialog.
<!-- zks:end -->
EOF
if [ ! -e "$AGENTS" ]; then
  (umask 022 && cp "$BLOCK" "$AGENTS")
elif ! grep -qxF "$BEGIN_MARK" "$AGENTS"; then
  # Append after one blank line, adding the missing final newline first if needed.
  if [ -s "$AGENTS" ] && [ "$(tail -c 1 "$AGENTS" | od -An -c | tr -d ' ')" != '\n' ]; then
    printf '\n' >>"$AGENTS"
  fi
  if [ -s "$AGENTS" ]; then printf '\n' >>"$AGENTS"; fi
  cat "$BLOCK" >>"$AGENTS"
else
  grep -qxF "$END_MARK" "$AGENTS" || die "$AGENTS has $BEGIN_MARK without $END_MARK; fix it by hand"
  awk -v blockfile="$BLOCK" -v begin="$BEGIN_MARK" -v end="$END_MARK" '
    BEGIN { while ((getline line < blockfile) > 0) block = block line "\n" }
    !done && $0 == begin { printf "%s", block; skip = 1; next }
    skip && $0 == end { skip = 0; done = 1; next }
    skip { next }
    { print }
  ' "$AGENTS" >"$TMP_DIR/AGENTS.md"
  # cat keeps the file's inode, mode and any symlink in place.
  cat "$TMP_DIR/AGENTS.md" >"$AGENTS"
fi

printf '==> zks doctor\n'
DOCTOR="$("$LAUNCHER" doctor)" || die "zks doctor failed"
printf '%s\n' "$DOCTOR"
INSTALL_STATUS="$(printf '%s' "$DOCTOR" | node -e 'let s = ""; process.stdin.on("data", (c) => (s += c)).on("end", () => { try { console.log(JSON.parse(s).install.status); } catch { console.log("unknown"); } })')"

cat <<EOF

zks $VERSION installed.
  app (read-only):  $DEST
  launcher:         $LAUNCHER
  integrity:        $INTEGRITY (install status: $INSTALL_STATUS)
  skill:            $SKILL_DIR/SKILL.md
  agent rule:       $AGENTS ($BEGIN_MARK ... $END_MARK)
EOF
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) printf '\nAdd %s to your PATH, for example in ~/.zshrc:\n  export PATH="$HOME/.local/bin:$PATH"\n' "$BIN_DIR" ;;
esac
printf '\nNext: zks auth set vercel|railway|supabase, aws sso login, gh auth login, then zks init in a project.\n'
[ "$INSTALL_STATUS" = "ok" ] || die "install status is \"$INSTALL_STATUS\", expected \"ok\""
