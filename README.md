# rspf

A Rust reimplementation of [pypolicyd-spf](https://launchpad.net/pypolicyd-spf)'s
functionality: a Postfix policy delegation daemon that checks the SPF
(RFC 7208) status of inbound mail and tells Postfix whether to accept,
reject, defer, or tag it.

## How this differs from pypolicyd-spf

- **Architecture.** pypolicyd-spf runs as a Postfix `spawn(8)` service:
  master.cf execs a fresh Python process per connection, talking the policy
  protocol over stdin/stdout. `rspfd` is instead a standalone, long-lived
  async daemon (built on `tokio`) that runs its own accept loop on a TCP
  and/or Unix socket. **Postfix does not spawn `rspfd`** — it's started
  independently (by a process supervisor such as daemontools) and Postfix
  connects to it as a client via `check_policy_service`, the same way it
  talks to postgrey, rspamd, or any other standalone policy daemon. See
  [`examples/postfix/main.cf.snippet`](examples/postfix/main.cf.snippet).
- **SPF engine.** Built on [`viaspf`](https://codeberg.org/glts/viaspf), a
  complete RFC 7208 implementation, rather than reimplementing SPF
  mechanism evaluation from scratch.
- **Config format.** A new TOML file (see
  [`config/rspf.toml.example`](config/rspf.toml.example)), not a parser for
  pypolicyd-spf's own `.conf` syntax. See the parameter mapping table below
  if you're migrating.
- **Additional features not in upstream pypolicyd-spf**: per-domain SPF
  record overrides, multiple external whitelist files, SASL/trusted-relay
  exemption, per-result reject/defer message templates, and SRS-unwrapping
  for forwarded mail. These were added deliberately, not ported.

## Install (Alpine Linux)

```sh
apk add cargo daemontools
cargo build --release
install -m 755 target/release/rspfd /usr/local/bin/rspfd
mkdir -p /etc/rspf
cp config/rspf.toml.example /etc/rspf/rspf.toml   # then edit it
```

Validate a config file without starting the daemon:

```sh
rspfd --config /etc/rspf/rspf.toml --check-config
```

Regenerate the shipped example config (kept in sync with the `Config`
struct, so it can never drift):

```sh
rspfd --dump-example-config > config/rspf.toml.example
```

## Running under daemontools

`rspfd`'s full application log (all levels, controlled by `[log] level`)
always goes to stdout, so it's meant to run under a supervisor that captures
that output, such as [daemontools](https://cr.yp.to/daemontools.html). See
[`examples/daemontools/rspfd/`](examples/daemontools/rspfd/) for a ready-made
service directory with a `run` script and a `log/run` script that pipes
output through `multilog`.

```sh
cp -r examples/daemontools/rspfd /etc/service/rspfd
mkdir -p /etc/service/rspfd/log/main
chmod +x /etc/service/rspfd/run /etc/service/rspfd/log/run
# svscan (or your init's equivalent) picks up the new directory automatically
```

Useful `svc` commands (see `svc(8)`):

```sh
svc -h /etc/service/rspfd    # SIGHUP: reload config/whitelist, no downtime
svc -d /etc/service/rspfd    # SIGTERM: graceful shutdown
svc -u /etc/service/rspfd    # start (if down)
```

`svc -h` triggers a hot-reload of `[skip]`, `[whitelist]`, `[policy]`,
`[relay]`, `[header]`, and `[messages]` from disk — no in-flight connections
are dropped. Note: `[spf]` and `[overrides]` are baked into the DNS
evaluator at startup and are **not** affected by a reload; changing those
requires a restart (`svc -t /etc/service/rspfd`, which stops then lets
`svscan` restart it).

### Mail-facility syslog mirror

In addition to the stdout log above, every evaluated request's decision is
also sent directly to syslog under the `mail` facility at `info` level,
tagged `postfix/rspfd` — the same facility (and a similar log style) Postfix
itself uses — so the two interleave in `/var/log/mail.log` (wherever your
syslog routes `mail.*`):

```
Jul 22 20:35:34 host postfix/rspfd[705106]: status=permit (Received-SPF: pass (domain of user@gmail.com designates 209.85.221.46 as pass, matched "ip4:209.85.128.0/17") ...), from=<user@gmail.com>, client=mail-wr1-f46.google.com[209.85.221.46], helo=mail-wr1-f46.google.com, spf_helo=none, spf_mailfrom=pass
```

`status` is `permit`, `reject`, or `defer`, matching Postfix's own
`status=sent`/`status=bounced`/`status=deferred` convention; the
parenthesized detail is the `Received-SPF` header text on permit, or the
reject/defer reason otherwise. `client` is `unknown[ip]` unless Postfix's
`reverse_client_name` attribute resolved. There's no queue ID: Postfix
doesn't assign one until `cleanup` runs after `DATA`, so at the RCPT stage
(this daemon's normal wiring point) it's always empty — logging a field
that's never populated wouldn't add anything.

This happens unconditionally (it isn't gated by `[log] level`) and is
independent of the stdout log; it's a direct `syslog(3)` call, not part of
the `tracing` pipeline. A missing or unreachable syslog daemon doesn't
affect the rest of rspfd — `syslog(3)` has no failure return value, so this
is inherently best-effort.

## Wiring into Postfix

See [`examples/postfix/main.cf.snippet`](examples/postfix/main.cf.snippet).
In short, add to `smtpd_recipient_restrictions`:

```
check_policy_service { inet:127.0.0.1:10045, default_action=dunno },
```

## Configuration reference

| pypolicyd-spf parameter | `rspf.toml` equivalent | Notes |
|---|---|---|
| `debugLevel` | `[log] level` | `"off"`\|`"error"`\|`"warn"`\|`"info"`\|`"debug"`\|`"trace"`; always logs to stdout |
| `HELO_reject` | `[policy] helo_reject` | `"fail"`\|`"soft_fail"`\|`"spf_not_pass"`\|`"never"`\|`"no_check"` |
| `Mail_From_reject` | `[policy] mail_from_reject` | same enum |
| `PermError_reject` | `[policy] permerror_reject` | bool |
| `TempError_Defer` | `[policy] temperror_defer` | bool |
| `skip_addresses` | `[skip] addresses` | list of CIDRs |
| `Whitelist` | `[whitelist] ips` | list of CIDRs |
| `HELO_Whitelist` | `[whitelist] helo_names` | exact match, case-insensitive |
| `Domain_Whitelist` | `[whitelist] domains` | suffix match against HELO/MAIL FROM domain |
| `Domain_Whitelist_PTR` | `[whitelist] domains_ptr` | suffix match against `reverse_client_name` |
| *(new)* | `[whitelist] files` | external whitelist files, `prefix:value` per line |
| `Lookup_Time` | `[spf] lookup_timeout_secs` | default 20 |
| `Void_Limit` | `[spf] void_limit` | default 2 |
| *(new)* | `[spf] max_lookups` | default 10; don't change unless you must |
| *(new)* | `[overrides]` | `domain = "v=spf1 ..."`, forces a record regardless of DNS |
| *(new)* | `[srs]` | SRS0 unwrapping for forwarded mail; see below |
| *(new)* | `[relay]` | SASL-authenticated / trusted-relay exemption |
| `Header_Type` | `[header] mode` | `"spf"`\|`"none"` (Authentication-Results style is not supported) |
| `Hide_Receiver` | `[header] hide_receiver` | bool |
| `Authserv_Id` | `[header] authserv_id` | optional string |
| `Reason_Message` | `[messages] fail`/`softfail`/`neutral`/`none`/`permerror`/`temperror` | one template per result, was a single setting upstream |

Full annotated reference: [`config/rspf.toml.example`](config/rspf.toml.example).

## Per-domain overrides

`[overrides]` lets you force a specific SPF record for a domain, bypassing
DNS entirely — including when that domain is reached transitively via
`include:`/`redirect=` from some other domain's record. Values are
validated as syntactically correct SPF records at config-load time, not at
request time.

## SRS (Sender Rewriting Scheme) unwrapping

When a message is forwarded through a relay that rewrites the envelope
sender (e.g. [postsrsd](https://github.com/roehling/postsrsd)) to keep SPF
passing at the forwarding hop, the *original* sender's domain is what SPF
should really be evaluated against for policy purposes. `[srs]` verifies an
`SRS0=HHH=TT=domain=local@rewrite-domain` address's HMAC against
`secrets` (which must match whatever secret your forwarding relay uses) and,
only if the hash is valid and not older than `max_age_days`, evaluates SPF
against the recovered `local@domain` instead of the literal rewritten
sender.

**This hash verification is load-bearing for security.** An implementation
that trusted the embedded domain without checking the hash would let anyone
forge an `SRS0=...=attacker-controlled-domain.com=...` sender and have SPF
evaluated against a domain of their choosing — likely one with no SPF
record at all, an automatic "none" rather than a hard fail. An invalid or
unrecognized hash always falls back to checking the literal, as-received
sender; it is never treated as an automatic pass.

## Security advisories

`cargo audit` (`cargo install cargo-audit`) currently flags two advisories,
both pinned by `viaspf`'s own `Cargo.toml` rather than anything in this
project's control: a `hickory-proto` DNS-message-encoding CPU exhaustion
issue (not believed exploitable here — we only ever encode simple
single-question queries) and an `idna` Punycode-normalization issue (matters
only if you configure `[overrides]`; see the ignore list for details). Both
are documented with rationale in [`.cargo/audit.toml`](.cargo/audit.toml)
and should be revisited once `viaspf` picks up fixed dependency versions.

## License

AGPL-3.0-or-later. `rspf` depends on
[`viaspf`](https://codeberg.org/glts/viaspf), which is itself
GPL-3.0-or-later; GPLv3 §13 and AGPLv3 §13 each explicitly permit combining
a covered work with code under the other license, with the combined work
then governed by AGPL-3.0-or-later, which is what this project uses.
