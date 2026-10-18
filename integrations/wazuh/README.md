# Wazuh: seeing cPanel logins that nothing else sees

## The problem this solves

Wazuh's bundled cPanel ruleset looks for `SUCCESS LOGIN` in `/usr/local/cpanel/logs/login_log`. Its own test
file ([`wazuh-ruleset/tools/rules-testing/tests/cpanel.ini`](https://github.com/wazuh/wazuh-ruleset/blob/master/tools/rules-testing/tests/cpanel.ini))
dates from 2016, and every successful-login case in it is a `login_log` line of this shape:

```
[2016-04-18 13:07:02 -0400] info [cpsrvd] 10.1.5.19 - root - SUCCESS LOGIN whostmgrd
```

**Current cPanel never writes that line.** Measured on two production servers, September 2026:

| | |
|---|---|
| `grep -c 'SUCCESS LOGIN\|SUCCEEDED LOGIN' login_log` | **0** |
| successful sign-ins those servers actually had, same week | **154** |

`login_log` now carries refusals only — `FAILED`, `DEFERRED`. A session that is **granted** is a `NEW` line in
`/usr/local/cpanel/logs/session_log`, which the stock ruleset reads only for logout events.

So a manager running the stock cPanel rules reports **zero successful logins** on a server being signed into all
day. Zero successful logins is indistinguishable, on a dashboard, from a server nobody has broken into.

Before trusting any tool on this — including this one — ask it the single question: *a successful login from
outside, do you see it?* If the answer is zero on a busy server, the tool is blind, not the server clean.

## Not every granted session is somebody typing a password

This is the distinction the rules exist for. cPanel reuses `handle_form_login` for sessions **derived** from an
authentication that already happened; `path` is what separates them.

| what the line says | what it means | rule |
|---|---|---|
| `method=handle_form_login`, `path=form` | the password was typed into the login form — **the finding** | 100210 |
| `method=CREATE_WEBMAIL_SESSION_FOR_SELF` | a mailbox opened its own webmail with its own password | 100211 |
| `path=loadsession` | a session opened **on behalf of** an identity — no password used | 100201 |
| `method=handle_auth_transfer` | WHM's "Log in as User" | 100201 |
| `possessed=1` | the operator is inside the account | 100201 |
| `method=create_user_session` | minted through the API by root | 100202 |

Deciding by `method` alone, measured against the real logs of two production servers, reported **68 sessions as
an accepted account password when no password had been presented** — including root opening a customer account
and a dozen mailboxes opened by their own cPanel account. That is the owner of the server doing their job. Alert
on it and the operator learns to ignore the whole rule group, which is worse than not having it.

## What is worth alerting on

The high-value rules are the correlations, because no single event looks wrong — the password **is** correct:

- **100220 / 100221** — one account signed into from 8+ different addresses in a day. This is the signal that
  found the live compromises: one account from 33 addresses across four continents in a week. Tune `frequency`
  to the estate; a shop owner on a phone plus an office is 2–3 addresses a day, not 8.
- **100222** — a correct password *after* a run of wrong ones. Only possible once both files are read, which is
  the reason this decoder exists.
- **100233** — a password change. Worth a rule for two opposite reasons: it confirms a reset you ordered took
  effect, and an unexpected one is an attacker locking the owner out.
- **100240** — the catch-all. Level 0, raises nothing, and it is not optional: a line matching no rule appears
  nowhere at all, so a session event cPanel starts writing after the next update would silently vanish and the
  dashboard would look exactly as it does now. Query for 100240; anything above the known count means cPanel is
  writing something these rules do not understand yet.

## Install

> **This section is a known violation of the provisioning rule** (project rules §5): the plugin must install
> these itself. Written out here only so the decoders can be tried by hand before that exists.

```
cp decoders/cpanel_session.xml       /var/ossec/etc/decoders/
cp rules/cpanel_session_rules.xml    /var/ossec/etc/rules/
/var/ossec/bin/wazuh-control restart
```

On each cPanel agent, in `ossec.conf`:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/usr/local/cpanel/logs/session_log</location>
</localfile>
```

Rule ids use the `100200`–`100299` custom block. Change them if that block is taken.

## Checking it before it goes near a manager

```
php test/logtest.php                                    # the shipped sample
php test/logtest.php /usr/local/cpanel/logs/session_log # a real log, run ON that server
```

`logtest.php` reads the same XML, applies the same PCRE2 in the same order, and reports what each line decodes to
and which rule claims it. It is **not** `wazuh-logtest`: it does not model frequency, `same_user`,
`different_srcip` or whole-ruleset ordering, and `wazuh-logtest` on a real manager remains the acceptance test.
Its job is to catch the cheap failures — a pattern that matches nothing, a field that comes out empty, a shape
that falls through.

Run against the real logs of two production servers:

```
  100210 3048    password accepted             7874 lines read
  100211    8    webmail password accepted     0 undecoded
  100201  798    operator, no password used    0 matched no rule
  100202   31    API-minted session
  100230  124    wrong password
  100231   14    session token refused
  100233  132    password changed
  100240    3    not yet classified
```

The 3,048 is the same number the SM Pro plugin counts from the same file with an independent implementation.

## Known limits

- **Wazuh cannot compare two decoded fields**, so "the session was created by a *different* identity than the one
  it belongs to" is not expressible. On both real logs that condition only ever co-occurred with `path=loadsession`,
  which is expressible, so the rules key on `path`. If cPanel ever writes `path=form` with a foreign `creator`,
  these rules would call it a password login. Nothing in two production logs did.
- A session restored for the *same* identity (`path=loadsession`, `creator` = the user) is classified here as
  operator activity. SM Pro calls that `restored`. Both agree it is not a password login; only the label differs.
- `session_log` records the address cPanel saw. Behind a proxy that is the proxy. Feed the agent the real client
  address, or correlate with the web logs, before acting on `srcip`.
