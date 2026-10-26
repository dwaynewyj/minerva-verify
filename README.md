# minerva-verify

`verify.mjs` checks a MINERVA evidence packet with nothing but Node.js 18 or later: no install,
no network call, no account.

```bash
node verify.mjs path/to/unzipped-packet
```

It recomputes every ledger row's hash and walks the chain, recomputes the SHA-256 of every file in
`SHA256SUMS`, reads each RFC 3161 time-stamp receipt in `anchors/` and finds the ledger row it
witnesses, walks the observation and validation-run chains, and verifies each daily checkpoint's
Ed25519 signature. It prints one `ok:` line per section and, when nothing failed, ends with one line:

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
https://minerva.studio/verify/verify.json.

## Licence

Apache License 2.0. Copyright 2026 Minerva Software Inc. See `LICENSE` and `NOTICE`.

This repository holds the verifier only; the MINERVA software itself is not open source.
