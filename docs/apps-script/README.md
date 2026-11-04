# Google Sheets audit mirror

The Sheet is a **mirror**. The source of truth is the local hash-chained log (`zks audit verify`) plus the providers' own logs (AWS CloudTrail, Vercel audit log, GitHub audit log). Anyone with edit access to a Sheet can change rows, so never treat it as tamper-proof evidence.

Records hold metadata only: id, time, human, agent, project, provider, target, environment, variable name, result and the provider version. There is no field for a value or a hash of a value.

## Setup (about five minutes)

1. Create a Google Sheet, for example "zks audit".
2. Open **Extensions → Apps Script**, replace `Code.gs` with [`Code.gs`](./Code.gs) and save.
3. Generate the HMAC key yourself, in a terminal the agent does not read:
   `openssl rand -hex 32 | pbcopy`
4. In Apps Script, open **Project Settings → Script Properties**, add `ZKS_HMAC_KEY` and paste the key.
5. Open **Deploy → New deployment → Web app**. Set "Execute as" to **Me** and "Who has access" to **Anyone**. Deploy and copy the `/exec` URL.
   "Anyone" is required because zks has no Google session. The HMAC signature is what keeps out other writers: unsigned or stale requests are rejected.
6. Store the key in the Keychain. A hidden dialog asks you to paste it:
   `zks auth set sheets-hmac`
7. Point zks at the web app and push the pending records:
   `zks config set sheets-webhook https://script.google.com/macros/s/<id>/exec`
   `zks audit sync`
8. Clear the clipboard: `pbcopy < /dev/null`.

After every `zks apply`, zks syncs automatically. If the webhook is unreachable, records stay pending locally and the next apply or `zks audit sync` retries them.
