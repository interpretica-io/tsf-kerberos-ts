# tsf-kerberos-ts

A Test Environment suite that exercises
[tsf-kerberos](https://github.com/interpretica-io/tsf-kerberos)
(`tapi_kerberos`) against a KDC / Active Directory the environment
points it at — getting a TGT and reading the KDC's security posture.

| Test | What it checks |
|---|---|
| `probe` | `tapi_krb5_get_tgt()` obtains a TGT for `TSF_KRB5_PRINCIPAL`/`TSF_KRB5_PASSWORD` and logs the ticket (client/server, validity, session-key enctype) |
| `audit` | `tapi_krb5_audit()` reports through tsf-cybersec — `krb5.preauth-not-required` (HIGH, AS-REP roasting), `krb5.weak-enctype` (MEDIUM) — gated on findings ≥ HIGH |

**Configure via env**: `TSF_KRB5_PRINCIPAL`, `TSF_KRB5_PASSWORD`,
optionally `TSF_KRB5_PREAUTH_PRINCIPAL` (and a resolvable realm/KDC in
the agent's `krb5.conf`). With none set, both tests **skip cleanly** —
no KDC to point at is not a failure.

## Authorized use only

The tests authenticate to a real KDC/Active Directory. Point them only
at a realm you own or are engaged to assess.

## Running it

```bash
./scripts/run.sh guess --cfg=localhost        # native; agent host needs libkrb5-dev
```

Needs `test-environment` beside the suite. The agent host must carry
**MIT krb5** with its development headers (`libkrb5-dev`). `tapi_kerberos`
reports through tsf-cybersec, so the suite builds the tsf-cybersec chain
(cybersec → kernel → devtool); refs are in `conf/external.yml`.

## Status

Written alongside tsf-kerberos; verified by building and running natively.
