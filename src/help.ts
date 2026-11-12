export const HELP_TEXT = `zks - zero-knowledge secrets and env vars for Vercel, AWS, GitHub, Railway and Supabase

Secret values never pass through argv, stdout, logs or the agent. zks reads them from a
source (1Password, Keychain, hidden dialog, generator or dotenv file) and writes them straight
to the provider after you approve a native dialog (Deny / Approve once / Always allow); writes to
a destination you chose "Always allow" for skip the dialog. Output is JSON with metadata only.

Usage:
  zks init [--policy FILE] [--project NAME]   Create a zks.policy.json template
  zks validate [--policy FILE]                Check the policy
  zks plan [--policy FILE] [--only A,B] [--target t1,t2]
                                              List the writes apply would make (no network)
  zks apply [--policy FILE] [--only A,B] [--target t1,t2] [--agent LABEL]
                                              Ask for approval, then write values to providers
  zks rotate NAME [--target t1,t2] [--policy FILE]
                                              Write a NEW value of a generated variable to its targets
                                              and its derived variables; always asks (no revocation)
                                              --target must cover every derived variable's targets
  zks inventory [--project P] [--policy FILE] Which variable is in which destination and how old
                                              (audit log metadata, no network)
  zks auth status                             Show which provider tokens are in the Keychain
  zks auth set <vercel|railway|supabase|sheets-hmac>
                                              Store a token through a hidden dialog
  zks auth delete <vercel|railway|supabase|sheets-hmac>
  zks capture read --space ID --page LABEL --selector CSS --store SERVICE/ACCOUNT [--click SELECTOR] [--origin ORIGIN]
                                              In an ego-browser page: click, read the token element
                                              into the Keychain, blank it (value never shown)
  zks capture fill --space ID --page LABEL --selector CSS (--store SERVICE/ACCOUNT --generate BYTES
                   | --from SERVICE/ACCOUNT) --origin ORIGIN
                                              Fill a new random (16-128 bytes) or a stored password
                                              into one password input of an ego-browser page; --from
                                              into another origin than the item came from asks first
  zks capture read --isolated --url URL --selector CSS --store SERVICE/ACCOUNT [--click SELECTOR] --origin ORIGIN
  zks capture fill --isolated --url URL --selector CSS (--store SERVICE/ACCOUNT --generate BYTES
                   | --from SERVICE/ACCOUNT) --origin ORIGIN
                                              Same, in a space zks opens itself in the capture-profile
                                              (not the agent's session) at URL, closed afterwards
  zks audit list [--limit N] [--project P]    Show audit records (metadata only)
  zks audit verify                            Check the audit hash chain
  zks audit sync                              Push pending audit records to Google Sheets
  zks trust list                              Show trusted destinations (writes there need no dialog)
  zks trust remove <key>                      Stop trusting a destination (no dialog needed)
  zks config show
  zks config set sheets-webhook <url>         Apps Script /exec URL for the audit mirror
  zks config unset sheets-webhook
  zks config set capture-profile <profileId>  Separate ego-browser profile for capture --isolated
  zks config unset capture-profile
  zks doctor [--fix]                          Check tools, tokens, audit and install integrity;
                                              --fix creates/chmods ~/.config/zks, ~/.local/state/zks
                                              (700) and their files (600) and lists what it cannot fix
  zks --version | zks help

Sources (variables.<NAME>.source.kind): op, keychain, prompt, generate, dotenv, public-key, template.
  generate format: random (bytes, encoding), uuid, jwt-secret, password (length 12-128, lower, upper,
  digits, symbols), rsa-private-key (bits 2048|3072|4096), ed25519-private-key
  public-key {of: "VAR"}: public PEM of VAR's generated private key; may be sensitive: false
  template {template: "postgres://\${USER}:\${PASS:url}@\${HOST}/db"}: built in memory, $\${ is a literal \${
Non-sensitive env vars may use "value" instead of a source. Sensitive ones never can.
Targets (targets.<key>.provider): vercel, aws-ssm, aws-sm, github, railway, supabase.
Capture: zks/<vercel|railway|supabase|sheets-hmac> only from their own site (--origin https://vercel.com,
https://railway.com, https://supabase.com, https://script.google.com); replacing an item asks first,
and a replaced item gets its old value back when the capture fails.

Exit codes: 0 ok, 1 a write or check failed, 2 usage or policy error, 3 not approved.
`;
