# TON Standard Smart Contracts — Bug Bounty Audit

**Date:** 2026-11-11 (WIB)
**Program:** TON Security Bug Bounty (README at `~/workspace/ton-bug-bounty/README.md`; self-check skill at `~/workspace/ton-bug-bounty/skills/bug-bounty-self-check.md`)
**Method:** Read-only static analysis of public source code, cloned locally. No exploit traffic, no state-changing tests against public mainnet/testnet nodes, public RPC/lite servers, real deployed contracts, or third-party services. No submission was made and the bounty bot was not contacted.
**Scope bar applied:** Only CRITICAL vulnerabilities qualify — unauthorized control/ownership or unauthorized manipulation of funds by an **unprivileged** attacker (no owner private key, no validator privileges, no prior control).

## Verdict: NO QUALIFYING FINDING

No candidate was found that plausibly meets the program's critical bar. Across all 17 in-scope contract targets, every funds-moving or control-changing path traced is gated on an owner signature, a threshold of signers, a registered validator, a deterministic proxy/payout-item address, or the elector/config system contracts — and no unprivileged-attacker path to unauthorized control or fund manipulation was established. **Submit nothing from this audit.**

This is a valid result, not a failure: these are mature, heavily audited standard contracts (several with professional audit reports on file), and a null result is the expected outcome.

## Repositories and versions reviewed

All repos cloned shallow into `~/workspace/ton-bug-bounty/audit-repos/` and verified by commit hash.

| # | Contract / version | Repository | Commit (HEAD at review) | Date |
|---|---|---|---|---|
| 1 | Elector | ton-blockchain/ton (master, sparse `crypto/smartcont/`) | `857b8a57a178e6ae0fe7fa86e7d81c5233de8560` | 2026-10-19 |
| 2 | Config | ton-blockchain/ton (master, sparse `crypto/smartcont/`) | `857b8a57a178e6ae0fe7fa86e7d81c5233de8560` | 2026-10-19 |
| 3 | Wallet v1 | ton-blockchain/ton (master, `simple-wallet-code.fc`) | `857b8a57a178e6ae0fe7fa86e7d81c5233de8560` | 2026-10-19 |
| 4 | Wallet v3 | ton-blockchain/ton (master, `wallet3-code.fc`) | `857b8a57a178e6ae0fe7fa86e7d81c5233de8560` | 2026-10-19 |
| 5 | Wallet v4r2 | ton-blockchain/wallet-contract | `68b56dc0f7f6a9d41a190a4c91f6dc68b18f0600` | 2025-05-23 |
| 6 | Wallet v5 | ton-blockchain/wallet-contract-v5 | `ff2a9cdb5abe3efdba1e773e4d03a53dea1550b1` | 2025-11-12 |
| 7 | tg-wallet-v1 | ton-blockchain/tg-wallet-contract | `1a29ae5d90e03c3d585d3e42e6ecef691d727a3c` | 2026-09-29 |
| 8 | Multisig V2 | ton-blockchain/multisig-contract-v2 | `9a4b13df6345c9c4068ca725e434b40f9ea5ca28` | 2025-01-28 |
| 9 | Highload V3 | ton-blockchain/highload-wallet-contract-v3 | `f5d9b592bd5ab5c9ae6ca627819929e140f6bd61` | 2025-05-27 |
| 10 | Single Nominator 1.0/1.1 | ton-blockchain/single-nominator | `b6455fcf7fbaf068d0fe723a5a11988ef67f6ea7` | 2024-11-26 |
| 11 | Nominator Pool V2 | ton-blockchain/nominator-pool-v2 | `ded2ad2918622afc5923f64ff2e4d2d871669cba` | 2026-09-28 |
| 12 | Jetton v2.1-tolk | ton-blockchain/acton-contracts (`jetton-v2.1/`) | `d721c3179696b453a9490fcfd2f30770f8c234b4` | 2026-09-17 |
| 13 | Jetton v2.0-func | ton-blockchain/jetton-contract (`jetton-2.0` branch) | `f2fb1fbb65d8e8ce6ec9f813f3e3dfab9268912a` | 2025-08-21 |
| 14 | Jetton v1.2-func | ton-blockchain/jetton-contract (master) | `d55f228edb0eb477cb4845d67e0dacc6489c6b57` | 2025-08-21 |
| 15 | NFT v1.1-func | ton-blockchain/nft-contract | `0b493104cd547d0fd52b7e6fd3c046fc365fe3d4` | 2025-06-10 |
| 16 | NFT v1.1-tolk | ton-blockchain/acton-contracts (`nft-v1.1/`) | `d721c3179696b453a9490fcfd2f30770f8c234b4` | 2026-09-17 |
| 17 | TON DNS | ton-blockchain/dns-contract | `d08131031fb659d2826cccc417ddd9b98476f814` | 2022-10-30 |

Notes:
- The `ton` repo was cloned with `--filter=blob:none --sparse`, sparse-checkout `crypto/smartcont/` only (the full repo is very large).
- The `jetton-2.0` branch was read via a separate `git worktree`; the master checkout was left undisturbed.
- `acton-contracts/dns/` (Tolk DNS) exists in the acton-contracts repo but is **not** a listed target in the program README (only `dns-contract` is), so it was not audited.
- In `nft-contract`, `nft-marketplace.fc` and `nft-sale.fc` are not the standard NFT target and were skipped.

## What was verified per group

### A. System contracts — Elector, Config, Wallet v1, Wallet v3 (reviewed directly)

**Elector (`elector-code.fc`, 1,187 lines, read in full).**
- `process_new_stake`: stake signature verified over `(tag, stake_at, max_factor, src_addr, adnl_addr)` with the validator's pubkey; `max_factor >= 0x10000` enforced; stake must match the current election (`stake_at == elect_at`), not be below `min_stake`, and not be below 1/4096 of accumulated total; one source address per validator pubkey. The signed data omits the stake amount, which is safe — the amount is the attached value the sender pays.
- `recover_stake`: credit is deleted from the credits dict before sending; the send uses mode 64 (carry-all-remaining-message-value), which returns only the attached incoming value, not the contract balance. (Send-mode semantics were verified against the official TON docs: mode 64 forwards the remaining incoming message value; mode 128 is the whole-balance mode. An earlier misreading of mode 64 as "send entire balance" was corrected — the elector's `return_stake` is correct.)
- Complaints (`register_complaint` / `register_vote` / `punish`): fine capped at the validator's frozen stake and must exceed the paid price; reward capped at `min(fine>>3, paid*8)`; `reward_addr` is forced to the complainer's address (not attacker-chosen); complaint keyed by `cell_hash` (duplicate rejected); votes require a signature from a current validator (weight from the current validator set); 2/3 threshold with per-round reset on validator-set change.
- `upgrade_code`: only from the config contract address (blockchain-authenticated sender). `config_set_confirmed`: only from the config contract. `try_elect` weight math (`(true_stake << 60) / best_stake`) cannot overflow at realistic supply magnitudes and divides only by a verified-nonzero `best_stake`. `unfreeze_*` fail closed (`throw_unless(59, total == tot_stakes)`).
- `run_ticktock` does one step per tick (conduct / install / announce / update-active / unfreeze). Bounced messages ignored (`flags & 1` is the `bounced` bit, after the 1-bit `$0` tag).

**Config (`config-code.fc`, 648 lines, read in full).**
- `recv_internal` set-next-validator-set (tag `0x4e565354`): sender must equal the elector address; vset validated (`0x12` tag, `main > 0`, `total >= main`, `t_since > now`, `t_until > t_since`).
- Proposal submission (tag `0x6e565052`): anyone may submit, but only creates a voting entry; hash/mandatory/critical/depth checks enforced; price must be covered by attached value; duplicates can only extend expiry.
- Vote paths (internal and external, tag `0x566f7465`): signature verified against the current validator set's pubkey for the claimed index; 3/4 weight threshold with `min_wins` rounds. The known conditional replay of a validator's positive vote across rounds is **explicitly excluded by the README** and was not reported.
- External dictator actions (`perform_action`): change-param, change-code, change-master-key, change-elector-code all require the config master public key signature plus strict seqno equality and `valid_until` — an attacker without that key cannot reach them. The dictator's broad power is by design (emergency key), not an unauthorized-control finding.
- `perform_proposed_action` for param `-999` (appoint/depose dictator), `-1000` (code upgrade), `-1001` (elector code) is reachable only via validator voting (3/4 weight, `min_wins` rounds) — governance by design.

**Wallet v1 (`simple-wallet-code.fc`, 25 lines) and Wallet v3 (`wallet3-code.fc`, 41 lines).**
- Both: strict seqno equality + signature over the post-signature body hash before any send; seqno bumped before sending. V3 additionally enforces subwallet-id equality and `valid_until > now()`. V1 has no expiry (known design limitation; seqno still prevents replay). No key-rotation entrypoint in either. No unprivileged path to move funds.

### B. Wallets — v4r2, v5, tg-wallet-v1, Highload V3 (delegated review)

- **Wallet v4r2** (`func/wallet-v4-code.fc`, 198 lines): signature over seqno-bound data verified before any op dispatch; seqno bumped and committed before dispatch; no key-rotation entrypoint (owner key immutable). Internal `recv_internal` only honors `plug`/`dstr` from owner-installed plugins (registry-gated); plugin fund release capped (`my_balance - msg_value >= r_toncoins`). Plugin file itself excluded per program rules and not audited.
- **Wallet v5** (`contracts/wallet_v5.fc`, 300 lines): signature is the trailing 512 bits; the signed slice includes the `signed_external`/`signed_internal` prefix, so internal↔external cross-replay is impossible. Signature verified before seqno/wallet-id/expiry checks. `verify_c5_actions` allows only `action_send_msg`; `action_set_code` / `action_reserve_currency` / `action_change_library` structurally excluded; exotic cells cannot pass the prefix check. Extension path requires the sender's hash in the owner-added extensions dict; `set_signature_allowed` reachable only from an extension; removing the last extension while signatures are disabled is blocked (no lockout/bricking).
- **tg-wallet-v1** (`contracts/WalletTg/*.tolk`, 203-line main): signature verified against `storage.publicKey` before any header validation or state change. Internal/external opcodes differ, so no cross-replay. Key rotation requires **two** signatures — outer current-key signature plus a rotation proof signed by the **new** private key over a payload bound to this wallet's address (`"KEY_ROTATION"`, workchain, address hash). Bulk sends length-checked; per-chunk `assertEnd()`.
- **Highload V3** (`contracts/highload-wallet-v3.func`, 244 lines): signature over `cell_hash(msg_inner)` verified before any state use; subwallet + stored-timeout equality; `created_at` within a `timeout` window (≤ ~48 days). Two-generation replay bitmap (`queries` / `old_queries`, 1023-bit cells); the bit is set and committed **before** the message-to-send is validated/sent; cleanup rotation keeps `old_queries` for `2*timeout`, strictly longer than the validity window, and the `created_at` check runs before the replay check — no replay-across-rotation hole. `recv_internal` requires the sender to equal the wallet's own address exactly (self-message only, content-bound to the owner's signature).

### C. Multisig V2, Single Nominator, Nominator Pool V2 (delegated review)

- **Multisig V2** (`contracts/multisig.func`, `order.func`, `order_helpers.func`, `messages.func`, `types.func`): `new_order` requires the sender to be the signer/proposer at the claimed index, with expiry checked and the proposer funding the order cost. `execute` requires the sender to be the deterministic order address for that seqno, `signers_hash` equal to the current signers dict hash, and `approvals_num >= threshold`, with expiry re-checked. `Order.approve` requires the sender to be a signer in the stored dict; double-approval rejected via the 256-bit mask. `update_multisig_params` (threshold/signers/proposers) reachable only from a threshold-approved order. Both professional audit PDFs in `audits/` (Zellic; Trail of Bits 2024-03 + fix review) were checked — the Trail of Bits high-severity findings are fixed in this commit (`threshold > 0`, `threshold <= signers_num` validated) and in any case required privileged signers.
- **Single Nominator** (`contracts/single-nominator.fc`, 221 lines, whole file): owner-only `WITHDRAW`, `CHANGE_VALIDATOR_ADDRESS`, `SEND_RAW_MSG` (arbitrary send with attacker-chosen mode), `UPGRADE` (`set_code`) — all require the owner key (out of scope: leaked-key/owner-compromise prerequisite). Validator-only `NEW_STAKE` / `RECOVER_STAKE`. All other senders: no state change, funds merely accepted.
- **Nominator Pool V2** (`contracts/Pool.tolk` 1,013 lines + `Proxy`, `PayoutItem`, `storage`, `nominators`, `validators`, `owner`, `messages`, `utils`, `types`, `fees`, `errors`, `config`, `opcode`, `Elector.types`): owner-only actions via `processOwnerAction` with per-branch re-checks (`AddValidator`, `RemoveValidator`, `OwnerWithdrawal`, `UpdateLimits`, `EvictNominator`, `UpdateNominatorsWhitelist`); init requires sender == pre-deployed owner. `NewStake` validator-only (sender in validators map, usage/parity/round/election-window checks; stake drawn from pool balance, validator attaches only ~1 TON gas). Proxy-only messages (`NewStakeOk`, `RecoverStakeError`) require the sender to equal the deterministic proxy address for that validator/parity. `PayoutBurnNotification` requires the sender to equal the deterministic payout-item address; the item can only burn when triggered by the pool or its predecessor, and forwards the pool-originated `Distribution` unchanged. Share-price accounting is accounting-based (`nominatorsAmount`), not balance-based, so donation attacks do not move the price. Withdrawal requires the sender to be a recorded nominator and pays only that nominator's own shares.

### D. Jettons, NFTs, DNS (delegated review)

- **Jettons v1.2-func / v2.0-func / v2.1-tolk**: mint, change-admin, claim-admin, drop-admin, change-metadata, and code-upgrade all require `sender == admin`. Claim-admin requires `sender == next_admin_address`, set only by the current admin. Wallet `transfer`/`burn` require `sender == owner` and `balance >= amount`. `internal_transfer` receipt requires `sender == minter` or the wallet deterministically derived from `transferInitiator`; burn notification requires the sender to be the wallet derived from `burnInitiator`, with the wallet deducting before sending, so `totalSupply` stays consistent. The v2.0-vs-v1.2 diff is only sharding (fixed-prefix-length wallet addresses) plus gas constants — no authorization change. The bounce-handler reasoning (see observation 1 below) was checked against the Tolk stdlib source and TON internal-message documentation.
- **NFTs v1.1-func / v1.1-tolk**: collection deploy / batch-deploy / change-owner / change-content require `sender == owner/admin`. Item init requires `sender == collection`. Item transfer requires `sender == owner` (editable-DRAFT: content edit and editorship transfer require `sender == editor`). Transfer excesses are computed from the balance including the incoming value minus a 0.05 TON storage reserve, so a transfer cannot drain the item's pre-existing balance.
- **TON DNS** (Func): root DNS has no state-changing entrypoint (`recv_internal` empty; `dnsresolve` is a pure getter over three hard-coded resolver addresses). The DNS collection only deploys a domain item if the caller pays `get_min_price()` for a valid 4–126-char `[a-z0-9-]` domain not blacklisted in masterchain config 80. Auction, transfer, `edit_content`, and `change_dns_record` all require `sender == owner`; bids require ≥105% of the current max bid with refund of the previous bidder; settlement pays the winning bid to the collection and sets the owner to the max bidder. Re-deploying an already-owned domain does not overwrite it (the initialized item refunds the redeployer).

## Excluded issues checked — NOT re-reported

| Excluded issue | Where checked | Result |
|---|---|---|
| Nominator Pool V2 #23 `RecoverStakeUnrestricted` | `Pool.tolk`, `sendStakeRecovery` (`storage.tolk`) | Same mechanism: anyone may trigger recovery, but funds return **to the pool**, not the caller. Not a new variant. |
| Nominator Pool V2 #24 `RecoverStakeError` deadlock | `RecoverStakeError` / `Proxy.tolk` error path | No freeze reported via this mechanism. |
| Nominator Pool V2 #25 `mulDivQuiet` zero-divisor | `utils.tolk`, `calcSharePrice`/`calcShareCount` | Zero divisor throws rather than minting/stealing; same family. |
| Nominator Pool V2 #26 `MAX_NM_DEPTH` deposit DoS | `storage.tolk` depth assert | Availability only, no fund theft. |
| Nominator Pool V2 #27 Deposit div-by-zero (`nominatorsAmount == 0`) | `storage.tolk` `DepositMessage` | Deposit rejected/refunded via the `TextComment` try/catch refund; same mechanism. |
| Nominator Pool V2 #28 / #29 `get_nominator_data` underflow | `Pool.tolk` getter | Getter-only throw on loss-making positions; no state or funds affected. |
| Elector `max_stake` accounting/recovery quirks | `elector-code.fc` `try_elect` / `unfreeze_*` | Known peculiarities; `unfreeze_*` fail closed (`throw_unless(59, …)`). Not reported. |
| Elector ignored-bounce semantics | `elector-code.fc` `recv_internal` | Bounced messages ignored by design. Not reported. |
| Config validator-vote replay across rounds | `config-code.fc` `recv_internal` vote path (comment in code: "by design config vote can be replayed onto the same proposal next round") | Explicitly excluded; not reported. |
| Wallet deletion / redeploy / reuse | Wallet v1/v3/v4/v5/tg-wallet/Highload | Deletion treated as final per program rules; no finding based on redeploy/reuse alone. |
| Wallet plugins | `wallet-contract` `simple-subscription-plugin.fc` | Excluded; not audited. |

## Most interesting non-qualifying observations (NOT reportable — do not submit)

These are real behaviors worth recording, but none meets the critical bar (each requires a privileged key, is an excluded-issue mechanism, is signer/owner-authorized behavior, or is availability-only with no unprivileged fund theft). Listed for completeness only.

**Wallets**
1. V5 / tg-wallet internal signed messages have no `commit()` before `process_actions`/sending, so a failed internal signed message rolls back the seqno bump and the same owner-signed message can be re-delivered by the relayer. Harmless: the replayed message is owner-signed, still bound by seqno + `validUntil`, and a failed attempt moves no funds (compute-phase throw rolls back c4/c5 atomically).
2. Highload V3: `bit_number == 1023` is unusable (not-found branch computes `store_zeroes(-1)`; found branch underflows). Covered by the repo's own test (`tests/HighloadWalletV3.spec.ts`, "should reject bitNumber = 1023"). Only makes that one query-id unusable for the owner.
3. V5 `process_signed_request` unconditionally stores `is_signature_allowed = true` — reachable only after a valid owner signature (documented recovery path for a mistakenly deployed wallet). No attacker path.
4. tg-wallet: trailing data after the bulk array is ignored (no ENDS check); v4 silently consumes seqno on an unknown op. Both are inside the signed payload — only the owner who signed it can supply them.
5. tg-wallet internal key-change sends its `OnKeyHasBeenChangedEvent` ext-out with `SEND_MODE_REGULAR` (no +2) — worst case the rotation rolls back if the balance cannot cover the event. Availability only.
6. Seqno is uint32 in v4/v5/tg-wallet (wraps after 2³² owner-signed messages) — requires the owner to sign ~4 billion messages; not attacker-reachable.

**Multisig / nominators**
7. Multisig: approvals after expiry are accepted by the Order (`approve`/`init`/`try_execute` perform no expiry check); only `multisig.func` `op::execute` checks `expiration_date >= now()`. A threshold-approved-but-expired order therefore sends its balance to the multisig in a message that throws. Confined to signers' own approved order and the multisig's own funds; no unprivileged attacker can create or approve an order.
8. Nominator Pool V2: immediate-deposit share-price timing — the immediate (non-pending) deposit path credits shares at the current `nominatorsAmount/poolSupply` price, so a deposit just before a `RecoverStakeOk` profit booking dilutes existing nominators. In the normal state (stakes outstanding) deposits go pending and are priced from the rotation-time `Distribution` snapshot, which neutralizes this; exploiting the immediate path requires the rare no-outstanding-stake state plus large capital for a small proportional profit. Authorized deposit at the published price, not unauthorized manipulation.
9. Nominator Pool V2: `RotationData.rotationCount` wraps at 255 (`(rotationCount + 1) % 0xff`); after ~254 rotations a usage record's count wraps to 0 and `checkRecoverRequirements` (`rotationCount >= 2`) blocks recovery until two more rotations. Multi-month, validator/elector-driven delay, not a permanent freeze or theft; no unprivileged attacker can force rotations.
10. Single Nominator: the validator chooses the elector `new_stake` pubkey/ADNL/signature (not bound to the registered validator) — the elector still returns recovered stake to this contract, so funds cannot be redirected; any effect requires the validator key itself.
11. Nominator Pool V2: `RemoveValidator` `activeValidators` counter leak — a banned validator whose usage later clears stays in the map without decrementing `activeValidators`, so repeated owner add/remove cycles could eventually hit `MAX_VALIDATORS = 32`. Owner-only trigger, minor availability effect on the owner, no fund impact.

**Jettons / NFTs / DNS**
12. Bounce handlers don't verify the sender — Jetton minter/wallet `on_bounce`/`onBouncedMessage` credit `totalSupply`/`jettonBalance` from a bounced `internal_transfer`/`burn_notification` without checking who sent the bounce. Dismissed: a bounced message is produced only by the network from a bounceable message the contract itself previously sent (body replaced by `0xFFFFFFFF` + first 256 bits of the original; the action phase rewrites/validates the relaxed message). The credited amount is always an amount the contract already deducted, delivered exactly once with the `bounce` flag cleared — no double-credit or forgery path for an unprivileged attacker. (This relies on protocol-level action-phase validation, not on the contract code itself.)
13. Jetton wallet excesses reserve math (Tolk v2.1 `toLeave = getOriginalBalance() − in.valueCoins + storageDue`): `getOriginalBalance()` is the balance at the start of the compute phase, i.e. after the incoming value is credited, so `toLeave` equals the pre-message balance plus storage due — same protection as the Func version. An attacker sending to a victim wallet with `sendExcessesTo = attacker` gets back only their own excess.
14. DNS auction refund cap (`amount_to_send = min(max_bid, balance − 1 TON)`) can leave a shortfall locked in the item if its balance ever fell below `max_bid + 1 TON`. Unreachable in a normal auction (balance only grows with bids; storage fees over a 1-week auction are negligible); the shortfall stays in the item, and the owner can extract it via transfer excesses.
15. DNS `dns_balance_release` lets anyone start a re-auction of a domain whose `last_fill_up_time` is >1 year old. Documented expiry mechanism: the current owner is refunded `balance − 1 TON`, the caller must pay `min_price`, and must still win a fresh 1-week auction.
16. DNS `process_governance_decision` can transfer/destroy a domain without the owner's consent — requires the domain's index in masterchain config parameter 80 with a valid op (privileged validator/governance action, not an unprivileged attacker).
17. Jetton v2.0/v2.1 sharding address derivation assumes a non-anycast `addr_std` — an anycast owner address would at worst produce a mismatched wallet address and failed transfers for that exotic owner (availability quirk, no attacker profit).
18. Minter `totalSupply` underflow on burn notification (no explicit check before `totalSupply −= amount`) — unreachable given wallet-side deduction plus derived-wallet sender verification; in Tolk a negative `coins` value would fail serialization and bounce the burn back to the wallet, restoring the balance.

**System contracts (Elector / Config)**
19. Config `unpack_proposal` getter: the code itself notes "there is a bug in config contract currently deployed in mainnet: wins and losses are messed up" — the getter returns wins/losses swapped in its output tuple. Getter-only display issue; no state, funds, or control effect.
20. Elector `unfreeze_*` throws (exit 59) if the frozen dict does not sum to `tot_stakes` — fail-closed, but a persistent mismatch would freeze that election's unfreeze (liveness, not theft). No attacker path to create such a mismatch was found; the sums are built by `try_elect` from the same members dict.
21. Config proposal spam: anyone may submit a voting proposal (paying the computed storage price), so the `vote_dict` can be grown at the proposer's expense. Each entry is self-funded by its price and expires; no unauthorized control or fund manipulation results.

## Limitations

- **Static analysis only.** No dynamic testing, fuzzing, formal verification, or local-emulator execution was performed (per task constraints). Findings that require a reachable-path proof beyond code reading were not pursued to execution.
- **Residual uncertainty.** The null result is a statement about the code as reviewed, not a proof of absence. The largest residual uncertainty is Nominator Pool V2 (~4,400 lines of Tolk with intricate round/payout state; reviewing subagent put its no-qualifying-critical confidence at ~80). The Jetton/NFT/DNS reviewer put its null-result confidence at ~85. The wallet reviewer and the direct Elector/Config review found no residual candidate above the bar.
- **Bounce-handler reasoning** (observation 12) rests on protocol-level action-phase validation of bounced messages rather than on contract code; if the network ever permitted sender-forged `bounced` messages, the Jetton accounting assumption would break — but that is a protocol property, not a contract bug, and is out of this program's contract scope.
- **No duplicate/known-report check against the bounty program's private intake** was possible; only the public README exclusions and the repos' own audit reports (Multisig Zellic + Trail of Bits; Highload V3 audit PDF) were consulted. A finding identical to an already-submitted report would be a duplicate even if technically valid.
- **Deployed-bytecode equivalence was not verified.** The review is of the named source revisions; it does not establish that any particular deployed contract's bytecode matches these sources.

## Recommendation

**Do not submit anything from this audit.** There is no candidate that plausibly meets the CRITICAL bar (unauthorized control/ownership or fund manipulation by an unprivileged attacker) in the reviewed revisions.

If the program later expands scope beyond Critical/unprivileged, the closest follow-ups (in order) would be observation 8 (Nominator Pool V2 immediate-deposit pricing) and observation 7 (Multisig expired-order approval) — both currently non-qualifying for the reasons stated.

If the user wants to keep hunting, the higher-yield next targets are outside this program's contract list (e.g. TON Blockchain Core components, which need a different skill set and a local node build), or a deeper dynamic review of Nominator Pool V2 with a local emulator — not a re-read of the same wallet/jetton code.

---
*Audit performed 2026-11-11 by the main agent (Elector, Config, Wallet v1/v3) with three delegated reviewers (wallets; multisig/nominators; jettons/NFTs/DNS). Repos under `~/workspace/ton-bug-bounty/audit-repos/`. Nothing was submitted; the bounty bot was not contacted.*
