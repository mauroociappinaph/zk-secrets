#!/bin/sh
# Installs zks for the current macOS user:
#   ~/.local/libexec/zks/<version>/   read-only app (dist, bin, production node_modules, sbom.cdx.json) and
#                                     tools.json: absolute paths of ego-browser, gh and op
#   ~/.local/bin/zks                  launcher with node, home and install path baked in; runs
#                                     node through `env -i` with a fixed PATH
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
# Fixed at install time so the launcher never trusts the caller's PATH or HOME.
NODE_BIN="$(node -p 'require("node:fs").realpathSync(process.execPath)')"
USER_NAME="$(id -un)"
USER_HOME="$(eval echo "~$USER_NAME")"
SAFE_PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
for baked in "$NODE_BIN" "$USER_HOME" "$USER_NAME"; do
  case "$baked" in
    "" | *[!A-Za-z0-9/._@+-]*) die "unsupported character in \"$baked\"; zks needs plain paths for node and your home" ;;
  esac
done
LIBEXEC="$USER_HOME/.local/libexec/zks"
DEST="$LIBEXEC/$VERSION"
BIN_DIR="$USER_HOME/.local/bin"
LAUNCHER="$BIN_DIR/zks"
CONFIG_DIR="$USER_HOME/.config/zks"
INTEGRITY="$CONFIG_DIR/integrity.json"
SKILL_DIR="$USER_HOME/.agents/skills/zks-secrets"
AGENTS="$USER_HOME/AGENTS.md"
BEGIN_MARK='<!-- zks:begin -->'
END_MARK='<!-- zks:end -->'

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

printf '==> Checking and building zks %s\n' "$VERSION"
npm ci
npm run check
printf '==> Checking dependencies (pinned versions, lockfile, npm audit)\n'
npm run --silent deps:check || die "dependency check failed (see the JSON above)"
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
# CycloneDX SBOM of the production dependencies, inside the install so the digest covers it.
npm run --silent sbom >"$DEST/sbom.cdx.json" || die "could not write the SBOM"
chmod 755 "$DEST/bin/zks"
DEST="$(cd "$DEST" && pwd -P)"
case "$DEST" in *[!A-Za-z0-9/._@+-]*) die "unsupported character in install path $DEST" ;; esac

printf '==> Writing launcher %s\n' "$LAUNCHER"
mkdir -p "$BIN_DIR"
if [ -e "$LAUNCHER" ] || [ -L "$LAUNCHER" ]; then
  chmod u+w "$LAUNCHER" 2>/dev/null || true
  rm -f "$LAUNCHER"
fi
cat >"$LAUNCHER" <<EOF
#!/bin/sh
# zks launcher written by install.sh. Do not edit: reinstall with ./install.sh instead.
# node runs through env -i with only HOME, USER, LOGNAME, LANG, a fixed PATH and the
# self-declared agent label; node, home and the app path were fixed at install time.
ulimit -c 0
if [ -n "\${PI_SESSION_ID:-}" ]; then ZKS_LABEL="pi:\$PI_SESSION_ID"; else ZKS_LABEL="\${AI_AGENT:-}"; fi
exec /usr/bin/env -i HOME="$USER_HOME" USER="$USER_NAME" LOGNAME="$USER_NAME" LANG=en_US.UTF-8 \\
  PATH="$SAFE_PATH" ZKS_AGENT_LABEL="\$ZKS_LABEL" \\
  "$NODE_BIN" --disable-warning=ExperimentalWarning "$DEST/dist/cli.js" "\$@"
EOF
chmod 555 "$LAUNCHER"

# zks never looks these up on PATH at run time: their absolute paths are fixed now, inside the
# install, before it turns read-only, so the integrity digest covers them. Missing tool: null.
# The stable `command -v` path is kept (not the versioned realpath) so upgrades keep working.
printf '==> Recording tool paths %s/tools.json\n' "$DEST"
# Each entry also pins the sha256 of the binary (symlinks followed): zks refuses to run a tool
# whose binary changed since install and `zks doctor` reports it as "changed".
tool_path() {
  found="$(command -v "$1" 2>/dev/null)" || found=""
  case "$found" in
    /*)
      sum="$(shasum -a 256 <"$found" 2>/dev/null | cut -d ' ' -f 1)" || sum=""
      node -e 'const [p, s] = process.argv.slice(1); if (!/^[0-9a-f]{64}$/.test(s)) throw 0; process.stdout.write(JSON.stringify({ path: p, sha256: s }))' \
        "$found" "$sum" 2>/dev/null || printf 'null'
      ;;
    *) printf 'null' ;;
  esac
}
EGO_PATH="$(tool_path ego-browser)"
GH_PATH="$(tool_path gh)"
OP_PATH="$(tool_path op)"
printf '{\n  "ego-browser": %s,\n  "gh": %s,\n  "op": %s\n}\n' "$EGO_PATH" "$GH_PATH" "$OP_PATH" >"$DEST/tools.json"
chmod 444 "$DEST/tools.json"
printf '    ego-browser: %s\n    gh: %s\n    op: %s\n' "$EGO_PATH" "$GH_PATH" "$OP_PATH"

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

- Do every secrets step yourself through the `zks-secrets` skill (`zks` plus `zks capture` in ego-browser): accounts, verification mail, token creation, storage and distribution to Vercel, AWS SSM/Secrets Manager, GitHub Actions, Railway or Supabase, for every kind of project.
- Never ask the human to create, copy or paste tokens, or to run setup commands (`zks auth set`, `security add-generic-password`). Ask only for a captcha, 2FA/passkey, browser-owned permission prompt or the zks approval dialog.
- Never see secret values: no `.env` files, Keychain reads, `vercel env pull`, `aws ... --with-decryption`, `op read`, and no snapshot, screenshot or read of a page while it shows a secret; let `zks capture --click` reveal it.
- If a user pastes a secret into the chat, do not use it and tell them to rotate it.
- zks writes to a new destination need the human's approval in a native dialog; never try to bypass or automate that dialog.
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
  launcher:         $LAUNCHER (node $NODE_BIN; reinstall after upgrading node)
  integrity:        $INTEGRITY (install status: $INSTALL_STATUS)
  skill:            $SKILL_DIR/SKILL.md
  agent rule:       $AGENTS ($BEGIN_MARK ... $END_MARK)
EOF
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) printf '\nAdd %s to your PATH, for example in ~/.zshrc:\n  export PATH="%s:$PATH"\n' "$BIN_DIR" "$BIN_DIR" ;;
esac
printf '\nNext: ask your agent to set up secrets; it creates and captures provider tokens itself with zks capture.\n'
[ "$INSTALL_STATUS" = "ok" ] || die "install status is \"$INSTALL_STATUS\", expected \"ok\""
