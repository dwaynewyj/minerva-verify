# minerva-verify

`verify.mjs` checks a MINERVA evidence packet with nothing but Node.js 18 or later: no install,
no network call, no account.

```bash
node verify.mjs path/to/unzipped-packet
```

It recomputes every ledger row's hash and walks the chain; checks every file against `SHA256SUMS`
and `manifest.json` and that nothing in the folder is unlisted; weighs who exported the packet and what
was withheld from them; reads each RFC 3161 time-stamp receipt in `anchors/` with the SCITT-shaped
record beside it and finds the ledger row it witnesses; walks the observation and validation-run
chains; verifies each daily checkpoint's Ed25519 signature and, where the checkpoint names its public-log entry, the DSSE envelope's signature over the same bytes; replays the AI agents' decision chains,
their seals and their approved policies; and checks every benchmark statement. It prints one `ok:`
line per section and, when nothing failed, ends with one line:

```
verified: mnv-verify/1 head <seq> <hash> manifest <sha256> at <UTC time> on <host>
```

On any failure it prints `not verified` and exits with status 1. A receipt's signature is left to
OpenSSL against the time-stamp authority's own chain; the script prints the command.

The canonical form (`mnv-canon/1`) is described at the top of the script, so the check can be
reimplemented in any language.

- What the packet holds and how it is checked: https://minerva.studio/verify
- The policy-key format: https://minerva.studio/policy-key
- MINERVA Studio, model and AI governance for Canadian financial institutions: https://minerva.studio

The same file is served at https://minerva.studio/verify/verify.mjs; its SHA-256 is published at
https://minerva.studio/verify/verify.json (this revision: `ec58c9dd8d78b4c5a91e3ebd749510b07ea946601a3793c6d4e53e84e8e43383`,
113,625 bytes). Without a terminal, https://minerva.studio/verify reads a packet's zip in the browser as a
first look — the first six sections — and sends the reader here for the verification line. The script
carries its licence as an SPDX header, so the copy inside every packet is licensed on its own.

- What an institution keeps if MINERVA disappears: https://minerva.studio/continuity

## Licence

Apache License 2.0. Copyright 2026 Minerva Software Inc. See `LICENSE` and `NOTICE`.

This repository holds the verifier only; the MINERVA software itself is not open source.
