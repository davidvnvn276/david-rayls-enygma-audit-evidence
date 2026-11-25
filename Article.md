# How can I make private stablecoin payments that regulators can still audit?

Use a shielded payment system that lets a public chain verify the transfer and gives a designated auditor separate, read-only access to its details. In [Rayls Enygma Public](https://docs.rayls.com/docs/enygma-public), a testnet pilot, payments are shielded from the public, not from the auditor.

Consider a business paying a supplier. An explorer can show that a transaction was recorded without revealing the invoice amount or naming the supplier. A reviewer needs more: the asset, the amount, the parties and the invoice the payment settled. I wanted to see where that extra evidence comes from, and what can actually be checked without an audit key.

## Start with who gets to read

| Approach | What the public can inspect | How an auditor gets more information |
| --- | --- | --- |
| [Circle’s USDC on Ethereum](https://www.circle.com/multi-chain-usdc/ethereum), ordinary ERC-20 transfer | The [token `Transfer` event](https://eips.ethereum.org/EIPS/eip-20#transfer-1) shows both wallet addresses and the amount. | Read the same event and join the addresses to the institution’s counterparty records. |
| [Aleo’s USDCx](https://aleo.org/usdcx/), private mode | Aleo keeps private records encrypted. Its [shielded USDCx bridge and wrapper](https://docs.aleo.org/build/common-uses/usdcx_bridge/index.html) are available on mainnet. | A holder can share a [record view key](https://docs.aleo.org/learn/core-concepts/public-and-private-state/index.html) to disclose one record without sharing the whole account history. |
| [Rayls Enygma Public](https://docs.rayls.com/docs/enygma-public), testnet pilot | The public sees the relayer, chain fee and cryptographic records. [Shielding and unshielding](https://docs.rayls.com/docs/enygma-public-who-sees-what) reveal a token, address and amount at the pool boundary. | The [deployment’s designated auditor](https://docs.rayls.com/docs/enygma-public-who-sees-what) has read access across its shielded payments. Rayls is the auditor on this testnet. |

The distinction is how disclosure begins. Aleo allows a holder to share a specific record. The Rayls pilot sets up audit access at registration, before any later request for a payment record. That broad access makes key custody a decision the institution needs to get right. [Rayls distinguishes the view key from the spend key](https://docs.rayls.com/docs/enygma-public-who-sees-what): audit reading does not grant the power to spend a note.

## What the public can verify

I traced **ten existing transactions** from 24 November 2026 on the [Rayls Public Chain Testnet](https://docs.rayls.com/docs/public-chain-reference): eight involving vault operations and two involving registration. I used the public RPC, Explorer and verified contract interfaces. I did not submit any of the transactions or open a live private record.

When a wallet [makes a shielded payment](https://docs.rayls.com/docs/how-enygma-public-works), it creates encrypted notes and a proof. A relayer posts the transaction. The vault records the notes that have been spent, using markers called nullifiers, and adds new commitments for the outputs. The public can inspect those recorded steps. The contents of the new notes are a different question.

The eight vault-related transactions all showed `Value = 0`, but they did not reveal the same information:

| Operation | What the raw receipt recorded |
| --- | --- |
| [One shield into the USDr vault](https://testnet-explorer.rayls.com/tx/0x3379d9458bec3275c5e578cd697aa3a268abec3ad58918dcdff91f0310483f1b) | A token `Transfer` recorded **10 test USDr** entering the vault. There was also an encrypted note. |
| Two unshields: [first](https://testnet-explorer.rayls.com/tx/0xcbf0f63894d58d3d1e85d5b2ecdffc0a43d1f331d2a75565ee9ccee320a3852b), [second](https://testnet-explorer.rayls.com/tx/0x74ea2ef5269beb130229d087b91a2f517815e2b0dd97d0bcf3901da377d12338) | The inner withdrawal call, vault event and USDr `Transfer` agreed on the public recipient and amount: **0.2** or **0.01 test USDr**. Both receipts also had encrypted notes from another call in the batch. |
| Three batches with a USDr-vault spend: [first](https://testnet-explorer.rayls.com/tx/0x3b5a53ab10aecb1d573e98d4e7adf400678e87119a6654c3fa4c364e9c747cab), [second](https://testnet-explorer.rayls.com/tx/0x99f104127c11a4f635fb950dae43a4ed1b4096f97298c66ad73857fd20ff5067), [third](https://testnet-explorer.rayls.com/tx/0x5a84068136fbc126a59cea8b0dc008ccf95c05de78d906395c3ed1db2190f450) | Each included a `transferV2` call to the dedicated vault. The receipts recorded spent-note markers and encrypted outputs, with no public token `Transfer` event. |
| Two direct shared-vault spends: [first](https://testnet-explorer.rayls.com/tx/0x02f3b9231d2b505a1036808b61df8f95ed95ea891786d20a54f037ec28ebc20e), [second](https://testnet-explorer.rayls.com/tx/0x1de52cba91c50961a39029ff661c6f891c558530ad8da1cd71a46bbb164bd07f) | The sampled note logs did not name an asset or show the payment amount. |

The practical trap is that an encrypted note can appear in the same receipt as a public amount. Both shortcuts, “zero Value means private” and “an encrypted note means private,” would have misclassified all three public deposit and exit examples. Read the emitting contract and the specific event before deciding what was disclosed.

## Same method, two different asset disclosures

One [Multicall3 batch](https://testnet-explorer.rayls.com/tx/0x5a84068136fbc126a59cea8b0dc008ccf95c05de78d906395c3ed1db2190f450) made the comparison particularly clear. Its two `transferV2` calls had the same outer transaction and the same method selector. One targeted the [dedicated vault](https://testnet-explorer.rayls.com/address/0x1edb224cf8637f92efadaf47ef9e70c044d75584); the other targeted the [shared vault](https://testnet-explorer.rayls.com/address/0x9c5ad5e5ea5b5910e7fd1e1cc7b70ce0e4bf06c2).

A follow-up read on 25 November returned the USDr token address from the dedicated vault’s asset getter. The shared vault returned the zero address for that getter, consistent with [Rayls’ description of a vault holding multiple assets](https://docs.rayls.com/docs/how-enygma-public-works). The dedicated vault identifies its asset through contract context. The shared call’s note logs left the asset unspecified. Neither result revealed the amount of the shielded payment.

I also decoded the calls rather than relying on the Explorer’s method labels. Across the eight vault-related transactions, **12 `transferV2` calls** supplied **26 encrypted outputs** that matched their emitted notes byte for byte. That includes separate fee calls. It is a count of calls and notes, not a count of customer payments. For all ten transactions, I rebuilt the transaction and receipt roots against their captured headers. Editing the logged deposit amount by one smallest unit changed its receipt root.

## What the registry provides to an auditor

In the pilot, the account wallet encrypts its view-key material to the deployment’s auditor. [The registry](https://testnet-explorer.rayls.com/address/0xa473291ffb33e2276f364fae169f03c4406719e9) makes the resulting encrypted fields available as part of registration. Access to the bytes is public; access to what they contain depends on the corresponding audit key. [Rayls documents the separation here.](https://docs.rayls.com/docs/enygma-public-who-sees-what)

I followed two registrations ([first](https://testnet-explorer.rayls.com/tx/0x96ee120814d5d95e9f74a0b0ef2848e2a9e9f8a770e64fc10d9e672d12d7083d), [second](https://testnet-explorer.rayls.com/tx/0xdfc7a8bd88d4ed9530b97f5eaa4ed82eb5be48f21e7146995204f914a800f8cc)). For both, the encrypted fields in the actual `register` call matched the `UserRegistered` log and the later `getAuditCiphertexts` read. Each contained a **1,088-byte ML-KEM capsule** and a **92-byte encrypted payload**. The registry’s **1,184-byte auditor public key** also matched the key fingerprint listed in the pilot app’s configuration. The sizes for the public key and capsule agree with [ML-KEM-768’s standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).

To test the difference between fetching and opening an envelope, I built a **separate local example** using fresh test keys and the design described in the [verified registry source](https://testnet-explorer.rayls.com/address/0x9686a3d5a9fd2101d15888c6a09a64fafa7ee349?tab=contract). The matching key opened the synthetic record. An unrelated key, a changed ciphertext byte and a capsule taken from a different envelope all failed authentication. The onchain observations establish that the two escrow records were published and could be retrieved. The local test illustrates the key boundary; it did not open either live record.

## How I would test this for a real payment workflow

Try the [official Rayls testnet walkthrough](https://docs.rayls.com/docs/try-enygma-public-on-testnet) with two test accounts. Fund one with test USDr and enough shielded test RLS for the relayer fee. If the USDr is still public, shield it before sending. Send to the second registered account and compare its wallet record with the public receipt. The recipient’s note [shows the amount and token, but does not carry the sender’s identity](https://docs.rayls.com/docs/enygma-public-who-sees-what).

For a trial with a supplier, keep the transaction reference with the invoice in a restricted record. If the transaction is batched, record which vault and which payment entry belong to that invoice. The sample with two `transferV2` calls shows why a hash alone can be too broad. Give the authorized reviewer a way to match the encrypted payment to verified counterparties and to record who requested and approved access. Run that retrieval as part of the trial.

The [FATF guidance on virtual assets](https://www.fatf-gafi.org/content/dam/fatf-gafi/guidance/Updated-Guidance-VA-VASP.pdf) treats handling originator and beneficiary information as a separate responsibility for covered transfers. The presence of an auditor key does not certify licensing, screening or reporting compliance. The useful acceptance test is whether an authorized reviewer can reconcile a specific invoice without making the supplier’s details public.

## How to recheck the evidence

The companion archive contains the RPC requests and responses, raw Explorer logs, transaction hashes, ABI slices and the offline verifier. `python -B verify_all.py` checks the file manifest and replays both evidence sets and the synthetic example. The files distinguish ten transactions, 12 inner calls and 26 encrypted outputs. RPC and Explorer may share an upstream feed. The replay checks public evidence against the saved headers. I did not independently run the Groth16 verifier, authenticate testnet consensus or test a production audit process.

## Sources

- [Rayls: how Enygma Public works](https://docs.rayls.com/docs/how-enygma-public-works), [visibility by role](https://docs.rayls.com/docs/enygma-public-who-sees-what) and [testnet walkthrough](https://docs.rayls.com/docs/try-enygma-public-on-testnet)
- [Circle: USDC on Ethereum](https://www.circle.com/multi-chain-usdc/ethereum) and [ERC-20](https://eips.ethereum.org/EIPS/eip-20)
- [Aleo: USDCx](https://aleo.org/usdcx/) and [record view keys](https://docs.aleo.org/learn/core-concepts/public-and-private-state/index.html)
- [NIST FIPS 203: ML-KEM](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) and [FATF: virtual-asset guidance](https://www.fatf-gafi.org/content/dam/fatf-gafi/guidance/Updated-Guidance-VA-VASP.pdf)
