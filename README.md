# cs-routeros-sync-bouncer

[![CI](https://github.com/ruokki/cs-routeros-sync-bouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/ruokki/cs-routeros-sync-bouncer/actions/workflows/ci.yml)

A CrowdSec remediation component for MikroTik RouterOS, written to survive
large blocklists on small routers.

## Why

The existing MikroTik bouncers push their full decision list to the router on
every cycle. The router has no way to tell a repeat from a new ban, so each
pass leaves another copy of the same address behind. With a Console
subscription feeding tens of thousands of decisions, the address-lists grow
without bound until the router runs out of memory.

cs-routeros-sync-bouncer never re-sends what is already there:

- **One address-list per family.** `crowdsec-v4` and `crowdsec-v6`, never a
  list per scenario or per blocklist.
- **The router is the source of truth.** Every pass reads the actual contents
  of the address-list and computes a difference. A steady state costs zero
  writes.
- **Addresses are compared canonically.** RouterOS reports `1.2.3.4/32` as
  `1.2.3.4`; comparing raw strings would see a difference on every pass and
  re-add the address forever.
- **Existing duplicates are collapsed.** If a previous bouncer already filled
  the list, cs-routeros-sync-bouncer removes the surplus copies on its first pass.
- **Entries carry a RouterOS timeout.** If this process dies, the router
  expires its own entries instead of holding them.
- **A hard cap bounds memory.** Past `max_entries`, decisions are dropped by
  priority - local scenarios, then blocklists, then CAPI - not by arrival
  order.
- **Manual entries are never touched.** Only entries commented `cs-routeros-sync` are
  managed.

## Install

Register the bouncer with CrowdSec first; the key goes in the environment, not
in the configuration file:

```sh
cscli bouncers add cs-routeros-sync-bouncer
export CROWDSEC_BOUNCER_KEY=...
```

### From source

```sh
go build -o cs-routeros-sync-bouncer ./cmd/cs-routeros-sync-bouncer
cp config.example.yaml /etc/crowdsec/bouncers/cs-routeros-sync-bouncer.yaml
```

### Container

Images are published to GHCR for `linux/amd64` and `linux/arm64`:

```sh
docker run -d --name cs-routeros-sync-bouncer \
  -v /etc/crowdsec/bouncers/cs-routeros-sync-bouncer.yaml:/etc/crowdsec/bouncers/cs-routeros-sync-bouncer.yaml:ro \
  -e CROWDSEC_BOUNCER_KEY \
  -e MIKROTIK_PASSWORD \
  ghcr.io/ruokki/cs-routeros-sync-bouncer:main
```

The image is distroless and runs as a non-root user; there is no shell in it.
If the LAPI runs on the host, either use `--network host` or point
`crowdsec.url` at an address the container can reach - `127.0.0.1` inside the
container is the container itself.

## RouterOS setup

Create a dedicated user restricted to the API. Give it `api` plus `read`,
`write` and `test`; it does not need `policy` or ssh access.

```
/user group add name=csbouncer policy=api,read,write,test
/user add name=csbouncer group=csbouncer password=...
```

Enable the TLS API and disable the plaintext one. `api-ssl` refuses the
handshake until a certificate is assigned to it, and RouterOS ships without
one, so create it first:

```
/certificate add name=api-ssl common-name=router
/certificate sign api-ssl
/ip service set api-ssl certificate=api-ssl disabled=no
/ip service set api disabled=yes
```

A `tls: handshake failure` at startup almost always means this step was
skipped. That certificate is self-signed, so keep `insecure_skip_verify: true`
unless you install one your host already trusts.

### The firewall rule is yours to write

cs-routeros-sync-bouncer only maintains the address-lists. It never creates, edits or deletes
a firewall rule, so it cannot lock you out of your own router. Add the drop
rules yourself, once:

```
/ip firewall raw
add chain=prerouting src-address-list=crowdsec-v4 action=drop comment="CrowdSec"

/ipv6 firewall raw
add chain=prerouting src-address-list=crowdsec-v6 action=drop comment="CrowdSec"
```

`raw` is deliberate: it drops before connection tracking, which is
significantly cheaper than `filter` on a router handling a large blocklist.

Put the rule where it will not shadow your management access - and confirm you
can still reach the router from an address that is not on the list before you
walk away from it.

## Run

```sh
./cs-routeros-sync-bouncer -config /etc/crowdsec/bouncers/cs-routeros-sync-bouncer.yaml
```

systemd:

```ini
[Unit]
Description=CrowdSec MikroTik bouncer
After=network-online.target crowdsec.service

[Service]
ExecStart=/usr/local/bin/cs-routeros-sync-bouncer -config /etc/crowdsec/bouncers/cs-routeros-sync-bouncer.yaml
Environment=CROWDSEC_BOUNCER_KEY=...
Environment=MIKROTIK_PASSWORD=...
Restart=always
RestartSec=10
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

On shutdown the address-list is left as it is. The entries carry timeouts and
expire on their own, so traffic stays blocked rather than being let through
the moment the bouncer stops.

## Sizing `max_entries`

`max_entries` is a guard against runaway growth, not a tight budget. An entry
costs roughly 100-250 bytes, so a large list is a small share of a modern
router's memory: 60000 addresses on a 1 GB device is about 1% of its RAM.

| Router                    | RAM      | Suggested |
| ------------------------- | -------- | --------- |
| hAP ax3, RB4011, RB5009   | 1 GB     | 150000    |
| hEX, hEX S, cAP ac        | 256 MB   | 50000     |
| hEX lite, older RB7xx     | 32-64 MB | 10000     |
| CCR, CHR                  | 4 GB+    | 0 (none)  |

Treat that table as a starting point and measure your own device. Add a batch
of throwaway entries and watch the memory move:

```
{
:local before [/system resource get free-memory]
:for i from=1 to=10000 do={
  /ip firewall address-list add list=memtest \
    address=("10.1." . ($i / 256) . "." . ($i % 256)) timeout=1h
}
:local after [/system resource get free-memory]
:put ("bytes/entry: " . (($before - $after) / 10000))
}

/ip firewall address-list remove [find list=memtest]
```

Multiply by the list size you expect and keep well clear of your free memory -
connection tracking needs room too.

If your subscription produces more decisions than the cap, prefer excluding a
specific blocklist by origin over letting the cap trim it arbitrarily.

Note that entries carry timeouts, which makes them *dynamic*: they live in RAM
only, never enter the stored configuration, and are gone after a reboot.
CrowdSec's initial snapshot restores them on the next start.

## Development

```sh
go test ./...
go test -race ./...      # needs a C compiler
go vet ./...
```

The logic that protects the router is in packages with no network dependency
and is tested directly:

- `internal/decision` - canonicalisation, deduplication, reference counting,
  origin priority and the cap.
- `internal/reconciler` - the difference between desired and actual router
  state, including duplicate collapsing and leaving unmanaged entries alone.
- `internal/crowdsec` - folding the LAPI stream into the desired state.

`internal/mikrotik` holds the RouterOS wire protocol; only its pure helpers are
covered by tests, and it is exercised for real against a device.
