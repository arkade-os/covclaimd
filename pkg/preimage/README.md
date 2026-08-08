# `pkg/preimage` — Preimage-claim plugins

Two `executor.Plugin`s that claim preimage-gated VTXOs the moment their
funding tx appears on the arkd tx stream. Both build the same claim tx and
submit it to the emulator; they differ only in how the `ClaimPacket`
(ECIES ciphertext + plaintext arkade script) reaches covclaimd:

- **Encrypted plugin** (`NewPlugin`): the maker stamps the packet into the
  tx's Arkade extension (`BuildPacket`).
- **Reveal plugin** (`NewRevealPlugin`): the maker submits the packet plus the
  funding output's hex BIP-371 taptree out-of-band via `RevealService`
  (`RevealPlugin.Submit`); the plugin verifies the packet against the taptree
  and keeps both in memory keyed by the funding output's pkScript. The stored
  taptree is what the claim is built from, so the funding tx itself needs no
  `TaprootTapTree`.

## Match

A tx output is claimed when **all** of the following hold:

1. A `ClaimPacket` is found — from the Arkade extension
   (`FindClaim`, `PacketType = 0x04`) or from the reveal plugin's in-memory
   map keyed by `hex(out.PkScript)`. Steps 2-4 are the encrypted path; the
   reveal path did them at submit time against the registered taptree, so it
   goes straight from the map hit to step 5.
2. `ValidateArkadeScript(packet.ArkadeScript)` passes — only
   `EnforcePayTo(receiverPk)` byte sequences are accepted.
3. `Decrypt(secretKey, packet.Ciphertext)` yields a 32-byte preimage.
4. The output's `POutput.TaprootTapTree` (BIP-371) decodes as a
   `TapscriptsVtxoScript` containing a `ConditionMultisigClosure` whose two
   keys are exactly `(signerPubKey, emulatorTweakedKey(arkadeScript))` and
   whose condition is `SIZE 32 EQUALVERIFY HASH160(preimage) EQUAL` for the
   decrypted preimage,
   and the output's pkScript equals the P2TR derived from that taptree.
5. The funding VTXO is still spendable per the indexer
   (`GetVtxos(WithScripts, WithSpendableOnly)`).

Any failure is a silent miss (debug log at most).

Produced intent: `MatchedClaim{Outpoint, Amount, Credentials{Preimage, ArkadeScript, Taptree, PkScript}}`.

## Solve

`BuildClaim` constructs the unsigned ark tx + checkpoint(s):

- Receiver output `(matched.Amount, receiverPkScript)` derived from the
  arkade script.
- Emulator extension output carrying the plaintext arkade script.
- Single VTXO input revealing the claim closure script + control block.
- `ConditionWitnessField` set to the preimage on the ark tx and every
  checkpoint.

The bundle is b64-encoded and sent to `Emulator.SubmitTx`. covclaimd never
signs and never holds funds. On failure the encrypted plugin just logs; the
reveal plugin keeps the submitted packet for retry (bounded by the
spendability gate) and removes it after a successful claim.

## Filter

Both plugins return `""` — no server-side CEL filter; matching is
structural in `Match`.

## Wiring

```go
cfg := preimage.Config{
    Indexer:             idxClient,      // spendability checks
    Emulator:            emulatorClient, // covenant signer; receives the claim bundle
    SecretKey:           secretKey,      // ECIES privkey packets are encrypted to
    EmulatorPubKey:      emulatorPub,    // from Emulator.GetInfo
    SignerPubKey:        signerPub,      // from arkd GetInfo
    CheckpointTapscript: checkpointBytes,
    Log:                 log,
}

encrypted, err := preimage.NewPlugin(ctx, cfg)

reveal, err := preimage.NewRevealPlugin(cfg) // also the RevealService backend via Submit
```

`cmd/covclaimd` enables each plugin behind `ENCRYPTED_ENABLED` /
`REVEAL_ENABLED` and exposes the covclaimd/emulator pubkeys over
gRPC + HTTP so makers can encrypt preimages against the right keys.

## Files quick-reference

- `plugin.go` — `Config`, `NewPlugin`, encrypted-path `Filter`/`Match`/`Solve`.
- `reveal_plugin.go` — `RevealPlugin`: `Submit` (write side, RevealService backend) plus `Match`/`Solve` over its in-memory registration map (process-local; lost on restart, makers re-submit). `Submit` accepts a packet only if the supplied taptree hashes to the swap address and holds the claim closure for that arkade script and preimage (`bindsToAddress`), so a registration can't be made for someone else's address. `matchRegistered` then matches on pkScript alone and builds the claim from the registered taptree. 15min TTL, 10k cap (`ErrRegistryFull`).
- `claimer.go` — shared core: packet validation, output matching, spendability gate, claim submission.
- `packet.go` — `ClaimPacket` TLV codec (`PacketType = 0x04`) and `FindClaim`.
- `claim.go` — `MatchedClaim`, `BuildClaim`, closure-search helpers.
- `contract.go` — `EnforcePayTo`, `CovenantClaimClosure`, `ValidateArkadeScript`, emulator key tweak.
- `crypto.go` — `Encrypt`/`Decrypt`: ECIES over secp256k1, HKDF-SHA256 → AES-256-GCM.
- `maker.go` — `BuildPacket`, funder-side helper producing the `extension.Packet`.
