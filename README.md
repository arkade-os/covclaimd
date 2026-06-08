# covclaimd

A claim daemon for the [Arkade](https://arkadeos.com/) protocol. `covclaimd` watches
the arkd transaction stream and, the moment a preimage-gated VTXO is funded,
sweeps it on the funder's behalf — decrypting the claim credentials on the fly
and forwarding the claim to a covenant emulator. The bot holds no funds and
signs nothing with its own key: the VTXO is spent through its covenant closure
using the revealed preimage. No wallet, no per-claim registration, no
persistence.

## How it works

A maker who wants the bot to claim a VTXO for them:

1. Fetches the bot's encryption key via `GetCovclaimdPubKey`.
2. ECIES-encrypts a 32-byte preimage (plus the receiver script) to that key.
3. Stamps the ciphertext into the funding transaction's Ark `OP_RETURN`
   extension as a `ClaimPacket` (TLV type `0x04`), and sets the VHTLC taptree
   on the funding output.

`covclaimd` then runs a match → solve loop driven by the
[`solver`](https://github.com/arkade-os/solver) executor over the arkd source:

- **Match** — for each streamed tx: parse the Ark extension, find a
  `ClaimPacket`, decrypt the preimage, validate the embedded arkade script
  (`enforcePayTo(receiver)`), and confirm an output whose taptree carries the
  expected `(serverPubKey, emulatorTweakedKey)` condition-multisig closure.
  A single I/O gate then checks the funding VTXO is spendable via the indexer.
- **Solve** — build the unsigned Ark tx + checkpoint(s) that spend the
  preimage-gated VTXO to the receiver, attaching the decrypted preimage as the
  condition witness, sign each PSBT, and submit the bundle to the emulator.

The matching, crypto, and claim-construction logic lives in
[`pkg/preimage`](pkg/preimage/README.md), which documents the protocol in
detail.

## Layout

| Path | Contents |
|---|---|
| `cmd/covclaimd` | Entrypoint: loads config, connects to arkd + the indexer, wires the plugin into the runtime. |
| `internal/config` | Environment-variable configuration (`COVCLAIMD_*`). |
| `internal/interface/grpc` | gRPC server + REST gateway exposing `PreimageService`. |
| `pkg/preimage` | The preimage-claim plugin: match/decode, claim build/submit, ECIES crypto. |
| `api-spec/protobuf` | Protobuf definitions and generated code. |
| `test/e2e` | Integration tests against a live arkd + emulator stack. |
| `test/docker-compose.yml` | The arkd / arkd-wallet / nbxplorer / emulator stack used by the e2e tests. |

## API

`covclaimd` serves gRPC (`COVCLAIMD_GRPC_PORT`, default `7070`) and a REST
gateway (`COVCLAIMD_HTTP_PORT`, default `7071`).

### `PreimageService.GetCovclaimdPubKey`

Returns the keys a maker needs to target this bot.

```
GET /v1/preimage/covclaimd-pubkey
```

```json
{
  "covclaimd_pub_key": "<33-byte compressed secp256k1 pubkey, hex>",
  "emulator_pub_key":  "<33-byte compressed secp256k1 pubkey, hex>"
}
```

- `covclaimd_pub_key` — the key makers ECIES-encrypt the preimage to.
- `emulator_pub_key` — the emulator signer key; makers MUST use it when
  building VHTLCs whose offline-claim closure is meant to be spent by this bot.

## Configuration

All configuration is via environment variables prefixed with `COVCLAIMD_`.

| Variable | Required | Default | Description |
|---|---|---|---|
| `COVCLAIMD_ARK_URL` | yes | — | arkd gRPC address (`host:port`). |
| `COVCLAIMD_EMULATOR_URL` | yes | — | Emulator (covenant signer) gRPC address (`host:port`). |
| `COVCLAIMD_SECRET_KEY` | effectively yes | zero key | Hex-encoded secp256k1 private key — the bot's ECIES identity, used to decrypt claim packets. **Not validated**: if unset it silently parses to a zero (insecure) key, so always set it explicitly. |
| `COVCLAIMD_GRPC_PORT` | no | `7070` | gRPC listen port. |
| `COVCLAIMD_HTTP_PORT` | no | `7071` | REST gateway listen port (must differ from gRPC). |
| `COVCLAIMD_LOG_LEVEL` | no | `4` (info) | logrus level (0=panic … 6=trace). |

## Build & run

Requires Go 1.26+.

```sh
make build      # builds ./covclaimd
make build-all  # cross-compiles release artifacts into ./build
```

```sh
COVCLAIMD_ARK_URL=localhost:7070 \
COVCLAIMD_EMULATOR_URL=localhost:7273 \
COVCLAIMD_SECRET_KEY=<hex-privkey> \
./covclaimd
```

### Docker

```sh
make docker          # build the production image
docker run --rm \
  -e COVCLAIMD_ARK_URL=... \
  -e COVCLAIMD_EMULATOR_URL=... \
  -e COVCLAIMD_SECRET_KEY=... \
  -p 7070:7070 -p 7071:7071 \
  covclaimd
```
