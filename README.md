# one-time-auth

One-time signing keys for a Sui account, as a thin wrapper over `@mysten/sui` 3.x.

A Sui signature carries the signer's full public key, so an account's key is exposed from its
first transaction on. `OneTimeAuth` never leaves a usable public key on chain: every transaction is
signed by a key that the same transaction retires, and the chain only holds a hash of the next
one. Between transactions, the account is protected by a hash and a PRF rather than by ECDSA.

It is built on Sui's address aliases (`0x2::address_alias`), which let an account replace the set
of addresses allowed to sign for it. Aliases are live on mainnet (protocol 116), testnet and
devnet.

Status: prototype. Mnemonic only, secp256k1 only, not audited.

## How it works

The account is the ordinary Sui address of the mnemonic's secp256k1 key (`m/54'/784'/0'/0/0`). It
is the sender of every transaction and never changes. What changes is who may sign for it.

**Keys.** With `seed` the BIP39 seed, `n` the group order and `G` the generator:

```
k    = HMAC-SHA512("OneTimeAuth/v1/key", seed)
s_i  = HMAC-SHA512(k, "OneTimeAuth/v1/salt" ‖ chain ‖ account ‖ LE64(i))  reduced to [1, n-1]
sk_i = sk_base + s_i  mod n
pk_i = pk_base + s_i·G
A_i  = blake2b256(0x01 ‖ pk_i)        the Sui address of pk_i
```

`chain` is the 32-byte genesis checkpoint digest and `account` the 32-byte account address, so a
key revealed on one network or for one account says nothing about the same index elsewhere.

`k` comes from the seed, not from `sk_base`. That matters: enrollment is signed by the base key,
which makes `pk_base` public, so anything computable from `sk_base` has to be treated as known to
an attacker who can break secp256k1.

**Enrollment** takes two transactions signed by the base key, because `enable` creates the alias
set and hands it to the account inside the call:

1. `address_alias::enable(0xa)` creates the alias set `{account}`.
2. `address_alias::replace_all(aliases, [A_0])` leaves `A_0` as the only signer.

After step 2 the base key is rejected, and so is every wallet that only knows how to sign with it.

**Each transaction** is signed with `sk_i` and ends with `replace_all(aliases, [A_{i+1}])`. A
programmable transaction is atomic, so the user's commands and the rotation succeed or fail
together.

**Recovery** needs only the mnemonic and the chain. The current index is the `i` for which `A_i`
equals the alias on chain, found by trying the last known index and its neighbours, then scanning.
There is no dependence on transaction history or an indexer, and an aborted transaction cannot
put the wallet out of step with the chain. Scanning costs one HMAC and one point multiplication
per index; persist the index with `onIndexChange` to skip it.

## Usage

```ts
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Transaction } from '@mysten/sui/transactions';
import { OneTimeAuth } from 'one-time-auth';

const client = new SuiGrpcClient({ network: 'testnet', baseUrl: 'https://fullnode.testnet.sui.io:443' });
const signer = await OneTimeAuth.fromMnemonic(mnemonic, {
	client,
	indexHint: loadIndex(), // optional
	onIndexChange: saveIndex, // optional
});

await signer.enroll(); // once per account

const tx = new Transaction();
const [coin] = tx.splitCoins(tx.gas, [1_000_000]);
tx.transferObjects([coin], recipient);

const result = await signer.signAndExecuteTransaction({ transaction: tx });
```

`OneTimeAuth` extends the SDK's `Signer`. `toSuiAddress()` is the account; `getPublicKey()` is the
current one-time key.

| Method | What it does |
| --- | --- |
| `sync()` | Reads the alias set and returns `not-enrolled` or `active` with the current index. |
| `enroll({ startIndex? })` | Hands the account to one-time keys. |
| `signAndExecuteTransaction({ transaction, skipSimulation? })` | Adds the rotation, builds, simulates, signs, executes. |
| `prepare(tx)` | Sets the sender and appends the rotation, for callers that build and submit themselves. |
| `signTransaction(bytes)` | Signs built bytes, only if they are sent by the account and rotate to the next key. |
| `rotate()` | Sends a rotation-only transaction. |
| `unenroll({ to })` | Replaces the alias set with `to` and returns the last index used. |

`sign`, `signWithIntent` and `signPersonalMessage` throw: a signature without a rotation would
reveal the current key and leave it in place.

To go through `client.core.signAndExecuteTransaction({ transaction, signer })` instead, call
`prepare(tx)` first and create the client with `restrictedMoveCalls: []`. The SDK refuses to build
calls into `0x2::address_alias` by default; `OneTimeAuth` lifts that for its own builds and
replaces it with a narrower rule, enforced at signing: the transaction must contain exactly one
`address_alias` call, and it must be the expected rotation.

## Failed transactions

A signed transaction that aborts on chain reverts its own rotation but has already published the
signer's public key. `signAndExecuteTransaction` deals with this in two ways:

- It simulates before signing and throws `SimulationFailedError` if the transaction would fail,
  so nothing is revealed.
- If the transaction fails anyway, it immediately sends a rotation-only transaction and then
  returns the failed result. If that rotation does not land, it throws `KeyExposedError`; call
  `rotate()` once the cause (usually gas) is fixed.

## What this protects against

After transaction `i` the public record holds `pk_base`, `pk_0 … pk_i` and the hash `A_{i+1}`. An
attacker who can extract secret keys from public keys learns `sk_base` and `s_0 … s_i`. To sign
next they need `s_{i+1}`, which is an HMAC-SHA512 output under a key derived from the seed, or a
preimage of a 256-bit address hash.

It does not protect against:

- **An attacker who breaks a key within seconds.** `pk_i` is revealed when the transaction is
  submitted. Validators check aliases when a transaction is submitted and voted on, not when it
  executes, so a forgery under `sk_i` that reaches them before they have applied the rotation can
  still be accepted. Revocation of the old key is eventual, not instant.
- **A stolen mnemonic.**
- **The window after a failed transaction**, until the follow-up rotation lands.

The additive form `sk_base + s_i` is no stronger than independent keys would be. It is there so
that the base key can later live in an MPC or HSM signer, and so that addresses can be derived
from `pk_base` and the salts without any secret key.

## Things to know

- One transaction at a time per account. Calls on one instance are queued; two processes with the
  same mnemonic will race, and the loser's transaction is rejected.
- Every transaction takes the alias set as a consensus-owned input, so it goes through consensus
  rather than the owned-object fast path.
- An index must never be used twice. `unenroll` returns the last one; pass `startIndex` above it
  if the account is ever enrolled again. `enroll` refuses to guess when the alias set has history.
- Handing the account back to its own address with `unenroll({ to: account })` does not restore
  protection, because `pk_base` has been public since enrollment.

## Development

```
pnpm install
pnpm test        # unit tests
pnpm test:e2e    # starts `sui start --with-faucet --force-regenesis`, or reuses a running localnet
```

`OTA_E2E_NETWORK=devnet pnpm test:e2e` runs the end-to-end suite against a public network.
