# Rayls Enygma Public: private stablecoin payments and audit access

Read the [article](Article.md) or open the [four evidence figures](visuals/CAPTIONS.md). This study follows ten existing transactions on the Rayls Enygma Public testnet. Eight involve vault operations; two are account registrations. The tests read public records only. The separate encryption demonstration creates new local test keys.

## Start here: run the complete check

Extract the distribution, or clone the repository, then open a terminal in the folder containing `README.md`, `verify_all.py` and `SHA256SUMS.txt`. Use a clean folder so that the file-coverage check can distinguish published files from unexpected ones.

Install Python 3.12 or 3.13 and [Node.js 24.22.3](https://nodejs.org/en/download/archive/v24.22.3). No `pip install`, `npm install`, wallet, RPC key or internet connection is needed once those runtimes are available. The synthetic test uses Node’s native ML-KEM and AES-GCM support.

On Windows in PowerShell:

```powershell
py -3 --version
node --version
py -3 -B verify_all.py
```

On Linux or macOS:

```bash
python3 --version
node --version
python3 -B verify_all.py
```

If you only have Python, append `--python-only`. This still checks **every packaged file** and reruns both public-data verifiers, the Python controls and the figure check. It prints a `SKIP` for the local synthetic encryption test. The complete GitHub Actions workflow always runs that test too.

The last line of a full run is `PASS: complete offline replay.` Before that, you should see:

- SHA-256 and manifest coverage for every payload file, including the workflow, raw data, article, figures and code. The manifest itself is excluded by design.
- Eight vault-related transactions and two registration transactions, with the signed transaction hashes, transaction roots, receipt roots and captured block header hashes reconstructed.
- Twelve `transferV2` subcalls with 26 matching encrypted outputs, and two public exit calls decoded through the forwarder.
- Two registry envelopes matching calldata, event and the later getter responses. The public auditor-key fingerprint matches the captured pilot app configuration.
- Three Python negative controls and a local ML-KEM/HKDF/AES-GCM demonstration where only the matching test key opens the synthetic envelope.
- Four exact SVG rebuilds from the evidence JSON and a dimensions check for the PNG exports. The manifest separately checks the bytes of both formats.

## Inspect one case in a browser

1. Open the [10 test USDr deposit](https://testnet-explorer.rayls.com/tx/0x3379d9458bec3275c5e578cd697aa3a268abec3ad58918dcdff91f0310483f1b). Top-level native `Value` is zero. In its logs, look for the USDr `Transfer` from the contract ending `0400`, to the vault ending `5584`. The data word represents `10000000000000000000` raw units, or 10 test USDr. Also locate `EncryptedNote` in the same receipt.
2. Open the [two-vault batch](https://testnet-explorer.rayls.com/tx/0x5a84068136fbc126a59cea8b0dc008ccf95c05de78d906395c3ed1db2190f450). `extensions.json` expands the two child calls under the full transaction hash. They share a method selector but target different vaults. Their note data does not disclose a payment amount.
3. Open the [0.2 test USDr exit](https://testnet-explorer.rayls.com/tx/0xcbf0f63894d58d3d1e85d5b2ecdffc0a43d1f331d2a75565ee9ccee320a3852b), find the `PartialWithdrawal` event, and compare its recipient and amount to the USDr `Transfer`. Encrypted notes elsewhere in the receipt came from a separate batched call.
4. Open either [registration one](https://testnet-explorer.rayls.com/tx/0x96ee120814d5d95e9f74a0b0ef2848e2a9e9f8a770e64fc10d9e672d12d7083d) or [registration two](https://testnet-explorer.rayls.com/tx/0xdfc7a8bd88d4ed9530b97f5eaa4ed82eb5be48f21e7146995204f914a800f8cc). The transaction calls the gas forwarder; the registry emits `UserRegistered`. In the decoded event look for `mlKemAuditCt` and `aesAuditCt`. These are public ciphertext fields. The related JSON lists their dimensions and records the comparisons.

## Trace the numbers back to the raw files

| Claim | Saved path | How to read it |
| --- | --- | --- |
| Eight transactions for vault activity | `results.json`; `evidence/check-rpc*.json`, `evidence/audit-rpc*.json`, `evidence/selector-rpc*.json`, and paired Explorer files | Each JSON row identifies a transaction hash, block, UTC time, public asset amount if present, and reconstructed commitments. |
| One public deposit, two public exits, five other transactions containing shielded spends with no token `Transfer` | `results.json` | The deposit and the two direct shared-vault calls come from the saved first Explorer pages. The five remaining hashes are all `Nullifier` results for the USDr vault in the six recorded windows. These are selected examples, not an activity estimate. |
| Child call decoding and exact exposed fields | `extensions.json` under `call_paths` | The verifier decodes `aggregate3` and, for the exits, the nested verified `execute` call. For `transferV2` it matches the vault target, spent-note markers and ciphertext bytes in emitted notes, using the recorded statement layouts. |
| Two registry cases | `extensions.json` under `registry`; `evidence/registration-*-tx.json`, `evidence/registration-*-logs.json`, `evidence/registry_probe_rpc*.json` and `evidence/registry_recheck_rpc*.json` | The two cases are distinct `UserRegistered` results in the six saved windows. The verifier pairs each receipt, relayed register call, public key and encrypted envelope with the corresponding later getter responses. |
| Current app and contract identities | `evidence/registry-abis.json`, `evidence/pilot-app-config.json`, `evidence/verified-contracts.json` | Compare the recorded onchain runtime with the captured Explorer verified bytes. The app file records the relevant configuration excerpt and the SHA-256 of its source asset. Compare its embedded key fingerprint against Keccak of the registry’s public auditor key. |
| Crypto access test | `audit_envelope.cjs` | Node generates throwaway ML-KEM-768 keys and uses the verified source’s HKDF label and capsule as authenticated data. The test checks the demonstrated envelope format; it is not the pilot wallet software. |
| Figures | `visuals/`, generated by `tools/make_visuals.py` | SVGs are rebuilt in each full run; PNG bytes are covered by the manifest and their image dimensions are checked. |

To print reconstructed results without editing the archive:

```bash
python -B verify.py --json
python -B verify_extensions.py --json
```

The default commands separately compare the replayed JSON with `results.json` and `extensions.json`. A change to a logged amount breaks the receipt-root check in the included control. The targeted tests also reject a wrong vault, an encrypted note changed by one byte at the same length, and two real registry ciphertext pairs swapped between accounts. No synthetic inputs were sent to the network.

## GitHub Actions

The included [workflow](.github/workflows/verify.yml) runs on pushes, pull requests and manual dispatch. Ubuntu 24.04 uses Python 3.12.14; Windows 2025 uses 3.13.11. Both use Node 24.22.3 and run `python -B verify_all.py`. The two Python builds were chosen from the [official runner manifest](https://github.com/actions/python-versions/blob/main/versions-manifest.json). All action dependencies are pinned to commits. Git is told to preserve file bytes across platforms so that line-ending conversion cannot invalidate the manifest.

## What the evidence does and does not establish

- The point-in-time reads used the public [Rayls testnet RPC and Explorer](https://docs.rayls.com/docs/public-chain-reference). The code checks node results, Explorer presentation and exact byte commitments relative to saved headers. Those interfaces may share an upstream chain feed. No separate consensus trust anchor is established. The replay does not re-execute the verifier, independently verify Groth16 proofs, or reconstruct the verifier’s internal ciphertext-binding calculation.
- Latest block headers bracketing the dedicated/shared vault reads matched at block 25,495,637. Registry implementation matching was captured at block 25,497,545; the audited getter reads were bracketed at block 25,497,684. These are 25 November 2026 observations, after the transactions. The historical calls that returned pruned-state errors remain in the saved data. They are not interpreted as zero or as a successful historical storage proof.
- The registry results establish public storage and retrieval of the envelope bytes in the selected samples. The synthetic test uses local throwaway keys and is not evidence that the testnet auditor opened any live record. Byte lengths, note commitments and recipient address fields are not evidence of legal identity or readiness for regulated production use.
- For the design, see [How Enygma Public works](https://docs.rayls.com/docs/how-enygma-public-works), [Visibility by role](https://docs.rayls.com/docs/enygma-public-who-sees-what), and the [verified registry](https://testnet-explorer.rayls.com/address/0x9686a3d5a9fd2101d15888c6a09a64fafa7ee349?tab=contract) and [forwarder](https://testnet-explorer.rayls.com/address/0x12b6640048deb2e8ffda4bc10bb2a640b70eca6d?tab=contract) source links. The project is a testnet pilot; sample amounts are test tokens.
