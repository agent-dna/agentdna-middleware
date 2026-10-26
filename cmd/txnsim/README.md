# txnsim — end-to-end transaction simulator

`txnsim` exercises the middleware the way agent runtimes do: it submits
transactions through the `/rubix` proxy, plays the Rubix node (and the CBAC
decision service) to answer them with every success and failure mode, then
checks what landed in Postgres and what the dashboard API shows.

```
go run ./cmd/txnsim            # run everything
go run ./cmd/txnsim -list      # list scenarios
go run ./cmd/txnsim -run F1    # only scenarios whose ID/name matches the regexp
go run ./cmd/txnsim -v         # also print notes and middleware log tails
```

## What a run does

1. Picks a **scratch database** (see Safety) and creates it if missing.
2. `go build`s the middleware from `-repo` and starts it on a free port, from
   an empty work dir so the repo's `.env` is never loaded. Its only
   configuration comes from txnsim: the scratch DB, the fake Rubix node, the
   fake CBAC service and `ORG_ID=txnsim-org`.
3. Truncates the ingestion tables, then seeds one org user (with two DIDs)
   and one registered app.
4. Runs each scenario. After every scenario it checks **invariants** on each
   intent the scenario touched:
   - `interaction_ids` matches the stored rows
   - no orphan rows or orphan threats
   - every pending branch points at rows that exist
   - hop ids follow the trunk/branch scheme: contiguous, with a fork only
     after its shared prefix
5. Prints PASS / WARN / FAIL per scenario and writes `txnsim-out/report.json`.

The fake node answers according to an `X-Sim-Rubix` request header, which the
proxy forwards untouched:

| Endpoint | Behaviours |
|---|---|
| `/rubix/v1/tx` | success, `fail` (status=false), `empty-id`, `http500`, `nonjson`, `drop` (connection closed) |
| `/rubix/v1/signature` | success, `fail`, `no-children`, `empty-child`, `empty-txid`, `nonjson` |

## Safety

txnsim **truncates** every table it touches, so it refuses to run against your
app database:

- Default database: the `.env` `DATABASE_URL` with `_txnsim` appended to the
  database name (e.g. `agentdna` → `agentdna_txnsim`).
- `-db-url` must not point at the same host:port/db as `DATABASE_URL`, and its
  name must contain `txnsim`, `test` or `sim` (`-allow-any-db` overrides the
  name check only).
- Data is left in place after the run so you can inspect it. Every id starts
  with `txnsim-<runTag>-<scenario>-` and every DID with `did:sim:<runTag>:`.

## Reading results

| Status | Meaning |
|---|---|
| PASS | Behaviour and invariants are as expected |
| WARN | Works, but behaviour is questionable or a product decision (e.g. growing chains stored as branches); `-strict` turns these into failures |
| FAIL | Wrong or inconsistent data: a bug |

Exit codes: `0` all passed (warnings allowed unless `-strict`), `1` at least
one failure, `2` setup error. This makes it usable as a CI gate once the
current failures are fixed.

## Flags

| Flag | Default | |
|---|---|---|
| `-db-url` | derived from `.env` | scratch Postgres URL |
| `-repo` | `.` | middleware repo to build |
| `-out` | `txnsim-out` | binary, `middleware.log`, `report.json` |
| `-run` | all | regexp on scenario ID or name |
| `-strict` | false | warnings fail the run |
| `-create-db` | true | create the scratch DB if missing |
| `-allow-any-db` | false | skip the scratch-name check |
| `-timeout` | 10m | overall limit |
| `-v` | false | verbose output |

## Adding a scenario

Add an entry to `allScenarios()` in `scenarios.go` and write its function.
Inside a scenario:

- **Build envelopes:** use `t.Builder(name)` with `Root` / `Next` / `Join` /
  `Chain`. Options: `Code(n)`, `Payload(v)`, `AtEpoch(ts)`, `Unsigned()`.
- **Submit:**
  - `t.intent(nft, executor, newestEnvelope, txBehaviour, sigBehaviour)` for an
    intent workflow. An empty `sigBehaviour` means the tx is never signed.
  - `t.submit(TxBody(...), tx, sig)` for any other tx body.
- **Assert:**
  - `t.expectRows` checks exact ids and endpoints.
  - `t.expectPairs` checks endpoints only.
  - `t.expectGone` checks that nothing survived.
  - Also available: `t.Equal`, `t.Check`, `t.Warnf`, `t.Failf`.
- **Generate ids:** use `t.NFT(name)` and `t.DID(name)`, so runs and scenarios
  never collide.
