# TON Blockchain Core (C++) — Bug Bounty Audit

**Date:** 2026-11-11 (WIB)
**Program:** TON Security Bug Bounty (README at `~/workspace/ton-bug-bounty/README.md`; self-check skill at `~/workspace/ton-bug-bounty/skills/bug-bounty-self-check.md`)
**Method:** Read-only static analysis of public source code, cloned locally. No exploit traffic, no state-changing tests against public mainnet/testnet nodes, public RPC/lite servers, or any live network. No submission was made and the bounty bot was not contacted.
**Scope bar applied:** Only CRITICAL vulnerabilities qualify — a **single** remote request/message/block/transaction from an **unprivileged** attacker (no validator key, no leaked key, no prior host/file control, no faulty-quorum/majority precondition) that (1) unauthorisedly manipulates blockchain state or funds, (2) halts the network, or (3) halts a node. All README exclusions applied.
**Coordination:** Three parallel component audits (validator, full node / ADNL + overlay, Simplex), each writing its own report under `~/workspace/ton-bug-bounty/audit/ton-core/`; this document synthesises them.

## Verdict: NO QUALIFYING FINDING

No candidate was found in any of the three covered components that plausibly meets the program's critical bar. Across the validator, the full-node network surface, and Simplex, the pattern is the same: every path an unprivileged remote attacker can actually reach is defended before it touches an unchecked assumption — signature-checked or hash-bound before trust, error-returning (not throwing) on malformed input, and quorum-gated before any state is applied. Every `CHECK()` / abort-class site traced either has its precondition established by an earlier guard in the same handler, is unreachable from attacker-controlled data, or requires quorum-signed / validator-controlled input — the faulty-quorum fail-stop class the program explicitly excludes as intentional. **Submit nothing from this audit.**

This is a valid result, not a failure: this is mature, heavily exercised core code, and it completes the TON audit arc — the earlier static smart-contract audit and the dynamic Nominator Pool V2 / Multisig emulator audit also returned no qualifying finding.

## Repository and version reviewed

| Item | Value |
|---|---|
| Repository | `ton-blockchain/ton`, `master` branch |
| Commit (HEAD at review) | `857b8a57a178e6ae0fe7fa86e7d81c5233de8560` (2026-10-19, TON v2026.10, merge PR #2597 from testnet) — verified with `git log` / `git rev-parse` |
| Checkout | Sparse checkout at `~/workspace/ton-bug-bounty/audit-repos/ton` (`validator/`, `adnl/`, `overlay/`, `crypto/`, `validator-engine/`, `common/`). Submodules (`td`, `tdutils`, `tdfec`, `third-party/*`) are **not** checked out. Local modifications: none. |
| `global_version` | **17** — `common/global-version.h`: `constexpr int SUPPORTED_VERSION = 17`. The live value is read from masterchain config parameter 8 (`GlobalVersion` record, `crypto/block/mc-config.cpp:277-288`, `mc-config.h:628`). Code branches up to `>= 16` were seen in the reviewed files; no `>= 17` branch exists yet in the reviewed files. `doc/GlobalVersions.md` describes versions 16 and 17 in this release (v16: out-msg-queue limits, dispatch-queue augmentation; v17: masterchain global-balance checking). The exact on-chain value was not re-fetched from a live node in this audit; findings are assessed against the code at this commit. |
| Prior audits (context, not redone) | `../smart-contract-audit-2026-11-11.md` (static, 17 standard contracts) and `../dynamic-np2-audit-2026-11-11.md` (dynamic emulator, Nominator Pool V2 + Multisig) — both NO QUALIFYING FINDING |

## Component 1 — Validator Node (block/transaction validation & cell parsing)

**Report:** `ton-core/validator-audit.md` (90 lines)

**Files reviewed.** Read in full: `validator/impl/ext-message-checker.cpp`, `external-message.cpp`, `proof.cpp`, `message-queue.cpp`, `crypto/block/check-proof.cpp`, `output-queue-merger.cpp`, `crypto/vm/cells/MerkleProof.cpp`, `CellString.cpp`, `CellSlice.cpp` (load paths), `crypto/vm/boc.cpp` (deserialize paths). Read in large part: `validator/impl/accept-block.cpp` (precheck + proof creation), `check-proof.cpp`, `top-shard-descr.cpp`, `shard.cpp`, `ext-message-pool.cpp`, `crypto/block/transaction.cpp` (unpack, storage, gas, compute/VM, action phases, fee helpers), `block.cpp`, `block-parse.cpp`, `mc-config.cpp`, `DataCell.cpp`, `bigint.hpp`. Grep + spot reads: all 260 `CHECK(` sites in scope, all `.value()`/`.at()`/`.front()`/`.back()` sites in the hot files, divisions, `UNREACHABLE`, `CombineError` throws. `validate-query.cpp` (7,936 lines) and `collator.cpp` (~7,000 lines) got targeted rather than line-by-line review (recorded as a limitation).

**Why null.** The only attack surface an unprivileged attacker can reach with a single request is an **inbound external message**, and it is defended in depth at every layer: size/depth limits, error-returning BoC deserialization, quiet TLB unpacking, VM errors caught and converted to rejections, big-integer (`RefInt256`/`uint128`) fee/gas math with saturating `to_long()`. `precheck_header` unpacks blocks before signature verification, but only via `load_cell_slice_quiet` (returns false, never throws) and a `try/catch`-wrapped `unpack_block_prev_blk_try`; block bytes first pass error-returning `BlockQ::init`. Everything after that is quorum-gated, and `CHECK()` fail-stop under a faulty quorum is explicitly excluded as intentional. `FAIL_UNLESS` is a return-false macro, not an abort. Every `std::optional::value()` site checked is preceded by an explicit presence check on the same optional.

**Most interesting non-qualifying observations (NOT reportable — do not submit).**
1. `MerkleProofCombineFast::merge` `CHECK(csa.size_refs() != 0)` (`MerkleProof.cpp:226`) plus a latent null-deref shape — no production caller (only tests); production `combine` uses validator-generated proofs, and a ref-count mismatch needs a SHA-256 second preimage.
2. `MerkleProofCombine` / `MerkleUpdate::get_any_cell` `UNREACHABLE()` (`MerkleProof.cpp:288`, `MerkleUpdate.cpp:382`) — inputs are validator-generated proofs or quorum-signed block state updates; no proof the invariant can be violated.
3. `CellSlice::load` pruned-branch `CHECK` (`CellSlice.cpp:1129`) — provably unreachable; the same condition throws `VmVirtError{1}` two branches earlier. Redundant defense, not a bug.
4. `CellString::load` / `CellText::load` `CHECK(to.offs == (int)size)` (`CellString.cpp:79,196`) — two-pass deterministic invariant; reachable only through TVM string opcodes on contract-controlled data inside gas-limited VM execution.
5. `ExtMessagePool::cleanup_expired_messages` `CHECK(it != ext_messages_hashes_.end())` (`ext-message-pool.cpp:361`) — pure internal bookkeeping invariant; no attacker input can desynchronise the two structures.
6. `AcceptBlockQuery` / `CheckProof` `CHECK`s — all on internal query state or blocks/proofs that already passed root-hash and (for validation) quorum-signature checks; failure requires a faulty quorum or validator-side bug, both excluded.
7. `Transaction::prepare_compute_phase` `FAIL_UNLESS(sgn(balance.grams) >= 0)` (`transaction.cpp:1835`) — return-false, not abort; unreachable by construction (gas bought ≤ balance).
8. `TotalValidatorSet::at_weight` `CHECK(weight_pos < total_weight)` and hole-invariant CHECKs (`mc-config.cpp:1927,2009-2025`) — validator-set selection from validator-voted config; maintained by construction.
9. `BagOfCells::get_idx_entry_raw` `custom_index.at(index)` (`boc.cpp:949`) — can throw `std::out_of_range` in principle, but callers bound the index against `cell_count` first; no unguarded-throw path found on attacker-reachable input.

## Component 2 — Full Node network surface (ADNL / overlay / block & state download)

**Report:** `ton-core/fullnode-adnl-audit.md` (122 lines)

**Files reviewed.** ~20,800 lines across: ADNL (`adnl-packet/message/channel/query/ext-connection/ext-server/network-manager/peer-table/node`, plus `adnl-peer.cpp`/`adnl-local-id.cpp` where they call in), overlay (`overlay-manager/overlay/broadcast-plumtree/simple/twostep/fec/overlay-peers`), validator net downloaders + `full-node-serializer.cpp`, validator downloaders (`download-state`, `wait-block-*`), DB files where remote data reaches them, and `validator-engine.cpp` (full-node path only). Static analysis only; no live-network contact.

**Why null.** The surface is consistently defended in depth: ADNL packets are signature-checked before dispatch; overlay broadcasts are signature + size + date checked and only delivered after a SHA-256 match against the claimed data hash; downloaded blocks/states are hash-bound to already-validated identifiers (block `file_hash`, state `root_hash` from a validator-set-validated proof, split-state part hashes from a hash-validated header, archive import file-hash + proof checks) before being trusted. Every `CHECK()`/`LOG(FATAL)`/`UNREACHABLE()` in the reviewed files was traced, and none is reachable by a single unauthenticated remote packet — e.g. Plumtree re-checks duplicates after every `co_await`, FEC duplicate-part `CHECK`s are guarded by prior duplicate rejection, and split-state `merge()` FATALs are unreachable because merged content is fixed by authenticated hashes.

**Most interesting non-qualifying observations (NOT reportable — do not submit).**
1. Twostep FEC has no explicit `data_size <= 16 MiB` check before `Decoder::create` (`broadcast-twostep.cpp:~380-430`) — but `check_rules` + size rate-limiter bound it first (`precheck_new_broadcast` runs the rate limiter; a negative `int32` size becomes a huge `uint32` and is rejected). Residual: the RaptorQ decoder's internal allocation behaviour for a max-size parameter set could not be verified locally (`td/fec` submodule absent) — and any effect there would be resource exhaustion, which the program excludes.
2. Unbounded state/archive slice accumulation (`validator/net/download-state.cpp`, `download-archive-slice.cpp`) — a malicious peer answering full 2 MiB slices can make the node keep appending parts / growing a temp file indefinitely. Resource exhaustion / DDoS, explicitly excluded — and the peer is one the node itself chose to download from.
3. Split-state `merge()` FATAL on `VmError`/`VmVirtError` and `LOG_CHECK`s on `combine_with` (`validator/downloaders/download-state.cpp:107-124`) — unreachable from remote input: every merged part is SHA-256-checked against a hash in the split-state header, itself Merkle-proof-virtualised and hash-checked against a validator-set-validated proof link. Also the loop bound `1 << (split_depth - shard_prefix_length)` uses a `split_depth` from the persistent-state descriptor derived from validated masterchain state, not from a remote packet.
4. `WaitBlockData::got_static_file` `CHECK(sha256 == file_hash)` (`wait-block-data.cpp:249`) — local static file from disk, not remote input; a corrupt local file is a local-host issue, excluded.
5. `R.ensure()` before `move_as_ok()` on `get_block_handle` results — on create-if-missing or post-proof-validation lookups; tripping one needs a local DB/internal failure, not a remote packet.
6. `AdnlLocalId::deliver` / `deliver_query` call `td::TlParser(...).fetch_int()` in a VLOG for unmatched custom messages/queries (`adnl-local-id.cpp:105,127,130`) — reachable with an arbitrary (even empty) custom message after signature verification, so it was checked as a candidate. It could **not** be verified locally because the `td` submodule is absent and a fresh clone failed from this VM. It is **not** reported: `TlParser::fetch_int()` is used pervasively in logging paths and is designed to return 0 / set an error flag on short input rather than abort; an empty custom message crashing the node would be a long-standing, trivially-triggered defect in heavily exercised code. Residual uncertainty recorded honestly in Limitations.
7. `BroadcastFec` `CHECK`s (`broadcast-fec.cpp:86,95,110,147`) — guarded by duplicate-part and decoder-lifecycle checks; the size CHECKs are on the local sending path, not received data.
8. Plumtree `repair_query_finished` `CHECK(active_repair_queries_ > 0)` (`broadcast-plumtree.cpp:1745`) — increment/decrement paired in local code; a remote peer can only cause a repair query to be sent or answered, never invoke the decrement.
9. Overlay `bcast_gc` `CHECK(delivered_broadcasts_.erase(Id))` / size-equality CHECK (`overlay.cpp:683-685`) — `register_delivered_broadcast` inserts into the set and the LRU together and only on a fresh insert, so the two structures cannot desync via remote broadcasts.
10. `DownloadState` (net) `CHECK(!S.size())` after reassembly (`download-state.cpp:256`) — holds by construction (`sum_` is the exact sum of received part sizes).

## Component 3 — Simplex consensus message handling

**Report:** `ton-core/simplex-audit.md` (105 lines)

**Files reviewed.** Read in full: all listed `validator/consensus/simplex/` files (consensus, certificate, pool, votes, state, bus, candidate-resolver, candidate-broadcast-relay, collator-producer, collator-schedule, state-resolver, db, misbehavior, stats) and `validator/consensus/` files (block-validator, block-accepter, chain-state, payload, bridge, bus, private-overlay, block-sync-overlay, block-producer, window-producer, types), plus targeted reads of the overlay precheck/delivery path and validator-set weight cap. Cross-checked against the Simplex spec (docs.ton.org) and a public third-party audit of the same component (Tesserae Ventures, Mar 2026, testnet commit `3bb6abc`).

**Why null.** The threat model kills the attack surface: all Simplex messages arrive via the **private** consensus overlay (validators + delegated collators only; `check_src_peer` drops non-members). Votes require a validator's session-bound Ed25519 signature (sender identity comes from the overlay's ADNL map, not message bytes); certificates are self-authenticating (every signature verified, 2/3+1 weight threshold, duplicates rejected before summing, total weight capped at 2^61 so `total*2` cannot overflow); candidates require the expected leader's/collator's signature with size caps. Every remotely reachable CHECK either has its precondition established by an earlier guard in the same handler or requires quorum-signed input — the faulty-quorum class the program explicitly excludes as intentional fail-stop.

**Most interesting non-qualifying observations (NOT reportable — do not submit).**
1. **Honest-validator self-equivocation race: SkipVote + NotarizeVote for the same slot — STILL PRESENT in this commit** (alarm lacks a `voted_notar` guard; `try_notarize` never re-checks `voted_skip` after its awaits; startup bootstrap re-broadcasts SkipVote after restoring `voted_notar`; `check_invariants` doesn't flag notarize+skip). **Not reportable:** no single remote trigger (it is local validation-latency timing / own restart), impact is throughput degradation not a halt (slots get skipped, chain advances, skip back-off self-limits), and it was **already publicly reported** by Tesserae Ventures in Mar 2026 — duplicate risk. Mechanism confidence ~85, fit ~10.
2. `FinalCert` handler CHECKs (`!is_skipped`, notarized-block match) — forming both a SkipCert and FinalCert needs ≥1/3 Byzantine double-voters; excluded quorum class.
3. `Proven::as_signed_vote()` CHECK — unreachable: `create_cert` is gated on `!will_be_notarized()`, and `being_saved` is set synchronously before any certificate-proven vote can be stored. Flag-based invariant, noted as defense-in-depth only.
4. `.move_as_ok()` on broadcast-extra parse — gated: overlay `precheck_broadcast` parses the same extra with `CO_TRY` before delivery.
5. Third-party-audit findings 3–5 re-checked against this commit: empty misbehavior evidence (explicitly excluded MisbehaviorProof family), unimplemented FIXME misbehavior reports (validator-initiated), twostep replay amplification (DDoS, excluded).
6. `Vote::from_tl` `*result` deref, weight math, `skip_intervals_` lower_bound, pre-signature payload decompression (bounded caps), `ChainState::apply` LOG(FATAL) — each checked; no remotely triggerable hole.

## Excluded issues checked — NOT re-reported

| Excluded issue | Where checked | Result |
|---|---|---|
| `CHECK()` fail-stop under faulty quorum | Validator precheck/validation, Simplex FinalCert/Proven paths | All block/consensus crashes require quorum-signed malformed input; explicitly excluded as intentional |
| OOM / DDoS / resource exhaustion | Ext-message limits, mempool caps, state/archive slice accumulation, twostep replay amplification | Size-bounded or excluded regardless of impact |
| Validator-initiated attacks | Collator-generated proofs, top-shard descriptors, Simplex FIXME misbehavior reports | Attacker would need to be a validator/collator |
| Extra-currency assumptions | `CurrencyCollection` add/sub (`block.cpp:1957,1969`) | Dict-combine failures return `false`; excluded in any case |
| Timestamp overflows (2038/2106) | `validate-query.cpp` `gen_utime` checks | Only range/freshness checks; no overflow finding pursued |
| Simplex `MisbehaviorProof` absence | Simplex `misbehavior.h`, empty misbehavior evidence | Explicitly excluded; not investigated as a finding |
| Lite-server / unsynchronised lite-server issues | `validator/impl/liteserver.cpp` | Excluded by program; not audited as a target |
| Local-tool / debug-only paths | `crypto/block/dump-block.cpp`, `adjust-block.cpp`, `test-block.cpp` | Tool-only `throw IntError` paths; excluded |
| Nominator Pool V2 / contract issues (#23–#29 etc.) | Prior audits | Covered by the earlier contract audits, not re-reported here |

## Limitations (honest, cross-cutting)

- **Static analysis only.** No build, fuzzing, formal verification, or local-emulator execution was performed in any component. No build was attempted: no candidate finding emerged that required one to verify, and a full TON build on this VM (~6 GB RAM, ~1.5 shared CPUs) would be slow and OOM-prone; build feasibility is recorded as **not attempted, not needed for this verdict**.
- **Sparse checkout — submodules absent.** `td`, `tdutils`, `tdfec`, and `third-party/*` are not checked out, and a fresh `git clone` of `ton-blockchain/td` failed from this VM (no network auth path: `fatal: could not read Username for 'https://github.com'`). Consequences: RaptorQ/FEC decoder internals and `TlParser::fetch_int()` short-input behaviour are unverified beyond their callers (the largest residual uncertainty in the full-node audit); the td actor framework's uncaught-exception behaviour is unverified (relevant only if an unguarded throw exists on an attacker path, of which none was found); generated `ton_api.hpp` is not in the checkout, so the TL-fetch rejection guarantee for Simplex `Vote::from_tl` rests on standard codegen behaviour, not a read of the generated file.
- **Coverage gaps.** `validate-query.cpp` (7,936 lines) and `collator.cpp` (~7,000 lines) were reviewed by targeted grep of all `CHECK`/`.value()`/division/exception sites plus full reads of the highest-risk sections, not line-by-line. **TVM opcode internals** (`crypto/vm/` except `cells/` and `boc.cpp`) were not covered — the single largest remaining in-scope surface. Full-node server-side query handlers (`validator/full-node*.cpp`, custom/fast-sync overlays) were not audited as targets — only the shared serializer they call was reviewed. Liteserver is excluded by the program.
- **Residual uncertainty.** The null result is a statement about the code as reviewed, not a proof of absence. Largest residuals: (a) TVM opcode internals, (b) the two large validator files above, (c) hand-traced `skip_intervals_` invariant in Simplex (quorum-gated in any case), (d) `td` submodule internals named above.
- **No duplicate/known-report check against the bounty program's private intake** was possible; only the public README exclusions and public audit reports were consulted. A finding identical to an already-submitted report would be a duplicate even if technically valid.
- **Deployed-binary equivalence was not verified.** The review is of the named source revision; it does not establish that any particular deployed node's binary matches these sources.

## Recommendation

**Do not submit anything from this audit.** There is no candidate that plausibly meets the CRITICAL bar (unauthorized state/fund manipulation, network halt, or single-request node halt by an unprivileged attacker) in the reviewed revision, in any of the three covered components.

If the user wants to keep hunting in TON Core, the higher-yield next targets (in order) would be:
1. **TVM opcode implementations in `crypto/vm/`** (`cellops`, `arithops`, `contops`, `dict` handling of attacker-crafted contract code during collation) — the one large in-scope surface this audit did not cover.
2. **A dynamic test of the external-message path with a local node build and a fuzzer** over `create_ext_message` + `run_message_on_account`, which would convert this audit's static "guarded" claims into executed evidence (needs a build-capable machine; a full TON build is likely slow/OOM-prone on this VM).
3. **Full-node server-side query handlers** (`validator/full-node*.cpp`) plus targeted fuzzing of the ADNL/overlay/FEC deserialization paths.
4. Simplex needs no further work beyond the above — the component is well-gated, and its one known live issue (the self-equivocation race) is already publicly reported.

---
*Audit performed 2026-11-11. Coordinator synthesis of three delegated component audits: validator node (`ton-core/validator-audit.md`), full node / ADNL + overlay (`ton-core/fullnode-adnl-audit.md`), Simplex consensus (`ton-core/simplex-audit.md`). Repos under `~/workspace/ton-bug-bounty/audit-repos/`. Nothing was submitted; the bounty bot was not contacted.*
