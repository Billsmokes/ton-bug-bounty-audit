# TON Bug Bounty Audit

Independent security audit of TON components for the [TON Security Bug Bounty](https://github.com/ton-blockchain/bug-bounty) program. Read-only analysis of public source code — local static review and local emulator testing only. No exploit traffic against public networks, and nothing has been submitted to the bounty program.

**Program:** critical vulnerabilities only, up to **$100,000** per finding (Grams or USDt). Reports go to [@ton_bugs_bot](https://t.me/ton_bugs_bot). Scope: TON Blockchain Core (Validator Node, Full Node, Simplex Consensus), MyTonCtrl, and the standard smart contracts listed in the program README.

## Progress

| Target | Method | Status | Verdict |
|---|---|---|---|
| Standard smart contracts (17 contracts) | Static review | ✅ Done 2026-11-11 | No qualifying finding — submit nothing |
| Nominator Pool V2 + Multisig V2 | Dynamic testing (local emulator/sandbox) | ✅ Done 2026-11-11 | No qualifying finding — submit nothing |
| TON Blockchain Core (C++) | Static review (+ build if needed to verify) | 🔄 In progress | — |

## Reports

- `audit/smart-contract-audit-2026-11-11.md` — static audit of all 17 in-scope standard smart contracts (Elector, Config, Wallets v1/v3/v4r2/v5, tg-wallet, Multisig V2, Highload V3, Single Nominator, Nominator Pool V2, Jettons, NFTs, TON DNS). Every funds-moving and control-changing path traced; no unprivileged-attacker path to unauthorized control or fund manipulation found. 21 non-qualifying observations recorded.
- `audit/dynamic-np2-audit-2026-11-11.md` — dynamic audit of Nominator Pool V2 and Multisig V2 in a local emulator. The closest observation (immediate-deposit share-price timing, +37.68 TON on a 100,000 TON deposit) was reproduced and measured — it is authorized timing arbitrage at the published price, not unauthorized manipulation, so it does not meet the program's critical bar. The expired-order and donation probes confirmed no vulnerability.

## Notes

- A null result is a valid result: these are mature, heavily audited contracts, and the program only pays for critical bugs.
- This repo is independent work, not affiliated with the TON Foundation. A null result here is not a proof of absence of bugs.
- License: MIT.
