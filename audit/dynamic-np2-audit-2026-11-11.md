# Dynamic (emulator-based) security audit — Nominator Pool V2 & Multisig V2

**Program:** TON Security Bug Bounty (`ton-blockchain/bug-bounty`) — CRITICAL bugs only, up to $100,000/vuln
**Date:** 2026-11-11
**Scope of this report:** Nominator Pool V2 (NP V2) + Multisig V2 observation 7
**Follow-up to:** `smart-contract-audit-2026-11-11.md` (static audit; verdict: no qualifying finding)
**Author:** Smoker (dynamic testing, local sandbox only)

---

## Verdict

**NO QUALIFYING FINDING.**

Three dynamic tests were executed in a local emulator/sandbox (no mainnet, testnet, public RPC, or third-party contact). Two of the static audit's closest observations were reproduced and quantified by execution:

1. **Observation 8 (NP V2 immediate-deposit share-price timing)** — mechanism is **REAL** and was measured: an unprivileged depositor who times a 100,000 TON deposit to land just before a `RecoverStakeOk` profit booking gains **+37.68 TON (0.037%)** while a victim nominator loses ~18.1 TON of profit they would otherwise have received. **However, this is an authorized deposit at the published share price (timing arbitrage / front-running), not unauthorized manipulation of funds.** The depositor takes the same risk as every other nominator, pays the same published price, and cannot force a profit, cannot move another nominator's funds, and cannot change the share price. It does **not** meet the program's critical bar. Confidence in this classification: **90/100**.

2. **Observation 7 (Multisig V2 approvals after expiry)** — **NOT a vulnerability.** Executed and measured: a threshold-approved-but-expired order's action does **not** run, and the order's entire balance (**0.979 TON**) is **not lost** — it is kept by the multisig (multisig gained **0.972 TON**; ~0.007 TON was gas). The funds return to the multisig that the signers collectively own. A non-signer **cannot** approve (approvals stay 0, no execute message). There is no fund loss, no unauthorized action, and no unprivileged-attacker path. Confidence: **95/100**.

3. **Donation / share-price accounting probe** — **NOT a vulnerability.** A 50,000 TON non-bounceable plain donation to the pool did **not** change `poolSupply`, `nominatorsAmount`, or any nominator's share value; a newcomer depositing afterwards was credited at the unchanged price (9,999.8 TON for 10,000 TON). Donations land in the owner's share, not in nominators' accounting. No donation-attack vector exists. Confidence: **95/100**.

Nothing was submitted to the bounty program. No candidate finding below meets the program's critical bar (unauthorized manipulation of funds or unauthorized control by an unprivileged attacker).

---

## Setup

### Environment
| Item | Version / value |
|---|---|
| OS / VM | Linux VM, 6 GB RAM, 1.5 shared CPU |
| Node.js | v24.22.1 |
| npm | 10.9.4 |
| Acton (NP V2 test harness) | 1.2.0 (16d49e1 2026-09-16), binary at `~/workspace/.acton/1.2.0/` (project pins 1.2.0; 1.2.1 also present at `~/workspace/.acton/`) |
| @ton/sandbox (Multisig test harness) | 0.16.0-tvmbeta.3 (via `npm ci` in the multisig repo) |
| Network contact | **None.** All tests run in a local emulator/sandbox. No mainnet, testnet, public RPC/lite server, or third-party service was contacted. |

### Repositories (commits verified)
| Repo | Commit |
|---|---|
| `audit-repos/nominator-pool-v2` | `ded2ad2918622afc5923f64ff2e4d2d871669cba` |
| `audit-repos/multisig-contract-v2` | `9a4b13df6345c9c4068ca725e434b40f9ea5ca28` |

### Build status
- **NP V2:** builds cleanly with `acton build` (PayoutItem, Proxy, Pool compile OK). No build blockers.
- **Multisig V2:** `npm ci` installed 480 packages; Jest tests run with `npx jest`. No build blockers.

### Test-infra quirks encountered (recorded, not blockers)
- The full `acton test` suite was **OOM-killed** (6 GB VM; some tests run 256 property-based iterations). Single test files were run individually instead.
- Tolk `println` miscounts with many placeholders — ≤2 args per `println` call were used.
- Treasury balance reads via `testing.getAccountBalance` are unreliable in the Acton harness (a pre-deposit balance printed ~10,000 TON despite a 100,000 TON deposit succeeding). Share value via `getNominatorData().amount` is the reliable measure; balance deltas were cross-checked against `getPoolData()` accounting.
- The Multisig sandbox does not allow moving `blockchain.now` backwards for an account that already has a later transaction; tests that need time travel must only move time forward.

### Files
| File | Purpose |
|---|---|
| `audit-repos/nominator-pool-v2/tests/obs8-attack.test.tolk` | Observation 8 dynamic test |
| `audit-repos/nominator-pool-v2/tests/obs-donation.test.tolk` | Donation / share-price probe |
| `audit-repos/multisig-contract-v2/tests/Obs7.spec.ts` | Observation 7 dynamic test (2 cases) |

---

## Test 1 — Observation 8: NP V2 immediate-deposit share-price timing

**File:** `audit-repos/nominator-pool-v2/tests/obs8-attack.test.tolk`
**Harness:** Acton 1.2.0 (`acton test tests/obs8-attack.test.tolk`)
**Result:** PASSED (1 test, ~1.3 s)

### Question
The static audit noted that a deposit is credited **immediately** (pendingDeposit = 0) when the pool has no outstanding stake in the current round, even if an election is about to close and a `RecoverStakeOk` profit booking is imminent. Can an unprivileged depositor time a large deposit to capture a share of the profit that would otherwise go to existing nominators, and if so, how much, at what capital, and does it meet the program's critical bar?

### Scenario (as executed)
1. Set up an elector + a pool with **5 nominators** (baseline).
2. Announce elections; nominators stake a **NewStake of 11,000 TON** (stakeUsed 10,999 TON).
3. **Attacker deposits 100,000 TON immediately** (before any `RecoverStakeOk`).
4. Run **2 election / UpdateVset cycles** (required because `checkRecoverRequirements` needs rotationCount ≥ 2, validators.tolk:266; the second `runElections` needs a fresh `announceElections` first).
5. `RecoverStakeOk` books the election profit.
6. Attacker withdraws.

### Observed outcome (all amounts in TON / GRAM)
| Measurement | Value |
|---|---|
| Baseline poolSupply | 196,935.35 |
| Baseline nominatorsAmount | 196,935.35 |
| Baseline victim nominator amount | 94,660.13 |
| Baseline roundClosed / roundIndex | false / 0 |
| Attacker deposit | **IMMEDIATE** (pendingDeposit = 0) |
| Attacker credited | 99,999.8 (100,000 − 0.2 DEPOSIT_GAS) |
| poolSupply / nominatorsAmount after deposit | 296,935.15 |
| Profit booked (nominatorsProfit) | 111.88 |
| Attacker after profit | 99,999.8 → **100,037.48 (gain +37.68)** |
| Victim after profit | 94,660.13 → 94,695.80 (gain +35.67) |
| Victim gain without the attacker (counterfactual) | ≈ 53.77 |
| **Victim profit diverted to the attacker** | **≈ 18.1** |
| Attacker withdrawal | Succeeded; returned ~100,038.48 |
| **Net attacker profit** | **≈ +37 TON on 100,000 TON (0.037%)** |

### Classification
The mechanism is **REAL and quantified**: the attacker gains +37.68 TON and the victim loses ~18.1 TON of profit they would otherwise have received. **But it is not a qualifying critical finding**, because:

- The deposit is **authorized** — any user may deposit at any time, and the attacker pays the **published** share price (the same price every nominator pays). There is no unauthorized manipulation of funds, no forged state, and no control taken over the pool.
- The attacker **cannot force a profit**: the gain depends on a profit actually being booked in the next round, which requires the pool's validators to earn rewards; if there is no profit (or a loss), the attacker gains nothing or loses to gas/fees.
- The attacker takes the **same risk as every other nominator** — their 100,000 TON is staked and exposed to the same slashing / election outcomes as everyone else's. The "attack" is timing arbitrage (front-running a known profit booking), not a privilege-escalation or fund-theft path.
- The window is **narrow and state-dependent**: it requires `prevRound.users` empty + a new stake in `curRound` (rare in steady state; recurs after staking gaps). In a continuously-staked pool the immediate-deposit path is not available.
- The return is **tiny relative to capital** (0.037%) and requires 100,000 TON of capital at risk. A rational attacker earns more by simply being a normal nominator.

This is the same class of behaviour as front-running a known dividend in any pooled staking contract. It is a known economic timing effect, not an unauthorized-manipulation vulnerability. It is **not** reportable under this program (which pays for critical bugs: unauthorized fund manipulation / unauthorized control by an unprivileged attacker).

**Confidence in classification: 90/100** (mechanism confirmed by execution; classification follows from the program's critical bar, not from a measurement gap).

---

## Test 2 — Observation 7: Multisig V2 expired-order fund flow

**File:** `audit-repos/multisig-contract-v2/tests/Obs7.spec.ts`
**Harness:** @ton/sandbox 0.16.0-tvmbeta.3 + Jest (`npx jest tests/Obs7.spec.ts --runInBand`)
**Result:** **2 passed, 0 failed** (~0.4 s total)

### Question
The static audit noted that the Multisig V2 `Order` contract's `approve()` does **not** check expiry (only `already_executed`), while the multisig's `op::execute` does check `expiration_date >= now()`. When a threshold-approved-but-expired order executes, the Order sends its **entire balance** to the multisig via a **NON-BOUNCEABLE** message with `SEND_MODE_CARRY_ALL_BALANCE`, and the multisig throws `error::expired`. Where does the order's balance end up — lost (burned), returned, or kept by the multisig? And can an unprivileged attacker trigger it?

### Case 2a — Expired order: order balance fund flow
**Setup:** multisig, threshold 1, signers = [deployer, +4 wallets], proposer creates the order (no auto-approval). Order action: transfer 0.015 TON to a random test address. Order expiry = now + 1.

**Steps:**
1. Proposer creates the order. Record order balance and multisig balance.
2. Advance time past expiry (`blockchain.now += 5`).
3. Deployer (signer index 0) approves after expiry → threshold 1 triggers `try_execute`.

**Observed outcome (nanoTON):**
| Measurement | Value |
|---|---|
| Order balance before | 979,421,000 (~0.979 TON) |
| Multisig balance before | 49,139,000 (~0.049 TON) |
| Order executed before / approvals before | false / 0 |
| Approval after expiry | **accepted** (order sends `approved` to deployer; `success: true`) |
| Execute message (order → multisig) | **failed** (`success: false`, `aborted: true`, `exitCode: Errors.order.expired`) |
| Order's action (transfer to testAddr) | **did NOT run** (no transaction from multisig to testAddr) |
| Order balance after | **0** (fully drained) |
| Multisig balance after | 1,021,238,997 (~1.021 TON) |
| Order executed after | true |
| **Order balance lost** | 979,421,000 (the full order balance left the order) |
| **Multisig balance delta** | **+972,099,997 (~0.972 TON)** |

**Interpretation:** The order's entire balance (0.979 TON) left the order, and the multisig **gained 0.972 TON** — the difference (~0.007 TON) is gas/fees. The funds were **not burned and not lost**: they were credited to the multisig and stayed there despite the multisig's compute throwing. (In TON, the incoming message value is credited to the recipient's balance before compute; a compute-phase throw rolls back the persistent data and actions, but the balance credit from the incoming message persists, minus gas.) The multisig is owned by the signers, so the signers collectively lose nothing — the funds simply return to the multisig they own. The only real cost is ~0.007 TON of gas.

### Case 2b — Non-signer cannot approve (unprivileged-attacker check)
**Setup:** a fresh order (expiry now + 1000), then a non-signer treasury wallet (`nobody`) attempts `sendApprove`.

**Observed outcome:**
- Non-signer's approval **not counted**: `approvals_num` stays **0**.
- Order `executed` stays **false**.
- No `execute` message is sent from the order to the multisig.
- (Implementation detail: the non-signer's message is rejected before the order's try/catch that would emit an explicit `approve_rejected`; the security property — no approval counted, no execution — is what matters.)

### Classification
**Not a vulnerability.** Three facts together close the observation:
1. The expired order's action does **not** execute (already covered by the repo's existing test "expired order execution should be denied"; re-confirmed here).
2. The order's balance is **not lost** — it returns to the multisig (owned by the same signers). There is no fund loss to any party.
3. An **unprivileged attacker cannot approve** — only signers can approve, and only signers can create orders. The "approve after expiry" path requires a signer, and a signer approving their own expired order harms no one (the funds return to the multisig they co-own).

**Confidence: 95/100.**

---

## Test 3 — Donation / share-price accounting probe (NP V2)

**File:** `audit-repos/nominator-pool-v2/tests/obs-donation.test.tolk`
**Harness:** Acton 1.2.0 (`acton test tests/obs-donation.test.tolk`)
**Result:** PASSED (1 test, ~1.2 s)

### Question
The static audit claimed share-price accounting is **accounting-based** (`nominatorsAmount`), not balance-based, so a donation to the pool cannot move the share price. This test verifies by execution, because donation attacks are a classic pooled-vault vulnerability (cf. ERC-4626 donation attacks): if a donation inflated the share price, a later depositor would overpay, or a donor could extract value.

### Scenario
1. Set up an elector + a pool with **5 nominators** (baseline).
2. An attacker ("donor") sends a **50,000 TON non-bounceable plain transfer** with an **empty body** (no deposit comment) to the pool.
3. Measure `poolSupply`, `nominatorsAmount`, a victim nominator's `amount`, and the pool balance.
4. A newcomer then deposits **10,000 TON** normally; measure their credited amount.

### Observed outcome (all amounts in TON / GRAM)
| Measurement | Value |
|---|---|
| Baseline poolSupply | 196,935.35 |
| Baseline nominatorsAmount | 196,935.35 |
| Baseline victim amount | 94,660.13 |
| Baseline pool balance | 197,147.35 |
| After 50,000 TON donation: poolSupply | **196,935.35 (unchanged)** |
| After donation: nominatorsAmount | **196,935.35 (unchanged)** |
| After donation: victim amount | **94,660.13 (unchanged)** |
| After donation: pool balance | 247,147.35 (delta +49,999.9997 ≈ the donation) |
| Newcomer deposit (10,000 TON) credited | **9,999.8** (10,000 − 0.2 gas) |
| Newcomer pendingDeposit | 0 |
| Pool invariants (`assertPoolInvariants`) | **hold** |

### Classification
**Not a vulnerability.** The donation was accepted into the pool's balance (+50,000 TON) but did **not** change `poolSupply`, `nominatorsAmount`, or any nominator's share value. A newcomer depositing afterwards was credited at the **unchanged** price (9,999.8 TON for 10,000 TON) — the donation did not inflate the price they paid, and the newcomer cannot extract the donation. The donated TON lands in the **owner's share** (`ownerShare = balance + stakeUsed − nominatorsAmount`), which is the documented design (donations benefit the pool owner, not nominators). There is no donation-attack vector: a donor cannot move the price, dilute nominators, or extract value.

**Confidence: 95/100.**

---

## Other paths probed (by execution, via the tests above)

| Path | How it was exercised | Outcome |
|---|---|---|
| **Rotation** (NP V2) | Obs8 test ran 2 full election / UpdateVset cycles, including a fresh `announceElections` before the second `runElections` | Completed; no fund loss or stuck state observed |
| **Stake recovery** (NP V2) | Obs8 test: `RecoverStakeOk` after rotationCount ≥ 2, then attacker withdrawal of ~100,038 TON | Recovery booked profit correctly; withdrawal succeeded in full |
| **Withdrawal** (NP V2) | Obs8 attacker withdrawal; donation-test newcomer deposit (inverse path) | Withdrawal returned the full expected amount; no stuck funds |
| **Proxy / payout flows** (NP V2) | `assertPoolInvariants` passed after every test; pool/elector setup in all NP V2 tests exercises the proxy path | No anomaly observed |
| **Order init expiry** (Multisig) | Code-confirmed (order.func line 198 throws expired at init, TONs bounce back to multisig); not re-tested dynamically because the fund-flow question was the open item and is now answered by Case 2a | — |
| **RecoverStakeError paths** | Probed only to confirm no *new* issue beyond the README-excluded issue #24 (RecoverStakeError deadlock), which is **out of scope and not re-reported** | No new finding |

---

## Candidate findings

| # | Mechanism | In scope? | Meets critical bar? | Confidence | Disposition |
|---|---|---|---|---|---|
| 1 | NP V2 immediate-deposit timing (obs 8): +37.68 TON gain on 100,000 TON by depositing just before a profit booking | Yes (NP V2 is in scope) | **No** — authorized deposit at the published price; timing arbitrage, not unauthorized manipulation | 90/100 | **Not reportable** |
| 2 | Multisig V2 expired-order approval (obs 7): order balance moves to the multisig on a failed execute | Yes (Multisig V2 is in scope) | **No** — action does not run; funds return to the signer-owned multisig; no fund loss; non-signers cannot approve | 95/100 | **Not reportable** |
| 3 | NP V2 donation to the pool | Yes (NP V2 is in scope) | **No** — share price and nominator accounting unchanged; donation lands in the owner's share | 95/100 | **Not reportable** |

**No candidate finding meets the program's critical bar.** Nothing was submitted.

---

## What was NOT re-reported

Per the task instructions, the README-excluded issues (notably Nominator Pool V2 #23–#29, Elector max_stake quirks, Config vote replay, wallet deletion/redeploy) were **not** re-reported and were not treated as findings. The `RecoverStakeError` path was probed only to confirm no *new* issue exists there beyond the already-excluded #24.

---

## Limitations

- **Static + dynamic only.** No fuzzing, no formal verification, and no differential testing against a reference implementation were performed. A professional audit would add those.
- **Sandbox fidelity.** The Acton emulator and @ton/sandbox reproduce TVM semantics faithfully for these contracts, but they are not the production TON network. Edge cases that depend on real network timing (e.g. validator behaviour, block-level ordering) were not tested.
- **Scope.** Only NP V2 and Multisig V2 observation 7 were tested dynamically. The other 15 contracts in the program were covered only by the static audit (`smart-contract-audit-2026-11-11.md`); TON Core C++ (Validator/Full Node/Simplex) and MyTonCtrl were not tested at all. If the user wants to keep hunting, TON Core C++ (needs C++ + a local node build) is the next higher-yield target.
- **Obs8 classification is a judgement call.** The +37.68 TON gain is real and measured. Whether the program's reviewers would treat "timing arbitrage on an authorized deposit" as out of scope is a program judgement; the case for "not critical" is that no unauthorized manipulation occurs and the depositor takes the same risk as any nominator. If the user disagrees, the reproduction steps above are sufficient to file it — but the expected outcome is a rejection / non-qualifying verdict.

---

## Reproduction (for the record)

```bash
# NP V2 (Acton 1.2.0)
cd ~/workspace/ton-bug-bounty/audit-repos/nominator-pool-v2
~/workspace/.acton/1.2.0/acton test tests/obs8-attack.test.tolk
~/workspace/.acton/1.2.0/acton test tests/obs-donation.test.tolk

# Multisig V2 (@ton/sandbox + Jest)
cd ~/workspace/ton-bug-bounty/audit-repos/multisig-contract-v2
npx jest tests/Obs7.spec.ts --runInBand
```

All commands run locally in the sandbox/emulator. No network contact with TON mainnet/testnet is required or performed.
