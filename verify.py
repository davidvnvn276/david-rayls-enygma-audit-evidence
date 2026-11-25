#!/usr/bin/env python3
"""Recheck the frozen Rayls testnet study. Standard library; no network access."""
import argparse
import json
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from encoding import (address, check, digest, hbytes, hash_header, keccak256,
                      signed_type_two, singleton_root, type_two_receipt, word_address)


BASE = Path(__file__).resolve().parent
EVIDENCE = BASE / "evidence"
CHAIN_ID = 7295799
USDR = "0x0000000000000000000000000000000000000400"
DEDICATED = "0x1edb224cf8637f92efadaf47ef9e70c044d75584"
SHARED = "0x9c5ad5e5ea5b5910e7fd1e1cc7b70ce0e4bf06c2"
IMPL = "0xad9667049f14d1757d147f652c41dc241c57091c"
MULTICALL = "0xca11bde05977b3631167028862be2a173976ca11"
RELAY = "0xa5f0c684eb49866a9f62f901cd85f98a19da0ac8"
ZERO_ADDRESS = "0x" + "0" * 40
IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


def load(name):
    return json.loads((EVIDENCE / (name + ".json")).read_bytes())


def timestamp(x):
    return datetime.fromtimestamp(x, timezone.utc).isoformat()


def format_usdr(raw):
    return format(Decimal(raw) / Decimal(10 ** 18), "f")


def type_name(entry):
    t = entry["type"]
    if t.startswith("tuple"):
        return "(" + ",".join(map(type_name, entry["components"])) + ")" + t[5:]
    return t


def abi_signature(item):
    return item["name"] + "(" + ",".join(map(type_name, item["inputs"])) + ")"


def event_topic(sig):
    return digest(sig.encode("ascii"))


def selector(sig):
    return event_topic(sig)[:10]


def pair_batch(name):
    request = {q["id"]: q for q in load(name + "-request")}
    response = {r["id"]: r for r in load(name)}
    check(request.keys() == response.keys(), name + ": request/response IDs differ")
    return [(request[i], response[i]) for i in sorted(request)]


def get(pairs, method, params, occurrence=0):
    matching = [r for q, r in pairs if q["method"] == method and q["params"] == params]
    r = matching[occurrence]
    check("error" not in r and r.get("result") is not None, f"Missing {method} for {params}")
    return r["result"]


def raw_explorer(log):
    return (log["index"], address(log["address"]),
            tuple(x.lower() for x in log["topics"] if x is not None), log["data"].lower())


def raw_node(log):
    return (int(log["logIndex"], 16), address(log["address"]),
            tuple(x.lower() for x in log["topics"]), log["data"].lower())


def call_path(tx, methods):
    code = hbytes(tx["input"])
    if address(tx["to"]) != MULTICALL:
        op = "0x" + code[:4].hex()
        return [(address(tx["to"]), methods[op], None)]
    check("0x" + code[:4].hex() == selector("aggregate3((address,bool,bytes)[])"), "Multicall method")
    data = code[4:]

    def word(pos):
        check(pos >= 0 and pos % 32 == 0 and pos <= len(data) - 32, "Word bounds")
        return data[pos:pos+32]

    def number(pos):
        return int.from_bytes(word(pos), "big")

    start = number(0)
    n = number(start)
    slots = start + 32
    check(0 < n <= (len(data) - slots) // 32, "Invalid multicall length")
    calls = []
    for i in range(n):
        elem = slots + number(slots + 32*i)
        target = word_address(word(elem))
        allow_failure = number(elem + 32)
        check(allow_failure in (0, 1), "Invalid multicall flag")
        payload = elem + number(elem + 64)
        size = number(payload)
        check(4 <= size <= len(data) - payload - 32, "Invalid multicall call bytes")
        op = "0x" + data[payload+32:payload+36].hex()
        calls.append((target, methods.get(op, op), bool(allow_failure)))
    return calls


def check_inclusion(tx, receipt, block):
    tx_hash = tx["hash"]
    check(block["transactions"] == [tx_hash], "Expected one transaction in a block")
    check(tx["blockHash"] == receipt["blockHash"] == block["hash"], "Block hash reference")
    check(tx["blockNumber"] == receipt["blockNumber"] == block["number"], "Block number reference")
    check(int(tx["transactionIndex"], 16) == int(receipt["transactionIndex"], 16) == 0, "Position")
    check(tx_hash == receipt["transactionHash"], "Receipt identity")
    check(int(tx["chainId"], 16) == CHAIN_ID and int(tx["type"], 16) == int(receipt["type"], 16) == 2, "Chain or envelope type")
    payload = signed_type_two(tx)
    check(digest(payload) == tx_hash, "Signed transaction hash")
    check(singleton_root(payload) == block["transactionsRoot"], "Transaction root")
    status = int(receipt["status"], 16)
    gas_used = int(receipt["cumulativeGasUsed"], 16)
    check(status == 1 and gas_used == int(receipt["gasUsed"], 16) == int(block["gasUsed"], 16), "Status or gas usage")
    item, bloom = type_two_receipt(status, gas_used, receipt["logs"])
    check(bloom == hbytes(receipt["logsBloom"], 256) == hbytes(block["logsBloom"], 256), "Logs bloom")
    check(singleton_root(item) == block["receiptsRoot"], "Receipt root")
    check(hash_header(block) == block["hash"], "Header hash")


def verify():
    check(keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "Keccak-256 known answer")
    contracts = load("verified-contracts")
    check(all(v["verified"] for v in contracts.values()), "ABI must come from verified source metadata")
    methods = {}
    topic_names = {}
    for contract in contracts.values():
        for item in contract["abi_subset"]:
            sig = abi_signature(item)
            if item["type"] == "function":
                methods[selector(sig)] = item["name"]
            if item["type"] == "event":
                topic_names[event_topic(sig)] = item["name"]
    transfer = event_topic("Transfer(address,address,uint256)")
    check(transfer == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "ERC-20 event topic")
    get_asset = selector("getAssetContractAddress()")
    checked, newer, selection = (pair_batch(n) for n in ("check-rpc", "audit-rpc", "selector-rpc"))
    check(all(int(get(pair, "eth_chainId", []), 16) == CHAIN_ID for pair in (checked, newer, selection)), "RPC network")
    anchor = get(newer, "eth_getBlockByNumber", ["latest", False])
    check(anchor == get(newer, "eth_getBlockByNumber", ["latest", False], 1), "Latest block changed across state reads")
    check(hash_header(anchor) == anchor["hash"], "State-read block header hash")
    asset_by_vault = {}
    for vault, expected in [(DEDICATED, USDR), (SHARED, ZERO_ADDRESS)]:
        raw = get(newer, "eth_call", [{"to": vault, "data": get_asset}, "latest"])
        asset_by_vault[vault] = word_address(hbytes(raw, 32))
        check(asset_by_vault[vault] == expected, "Read-only vault asset identity")
    check(int(get(newer, "eth_call", [{"to": USDR, "data": selector("decimals()")}, "latest"]), 16) == 18, "Token decimals")
    sym = hbytes(get(newer, "eth_call", [{"to": USDR, "data": selector("symbol()")}, "latest"]))
    check(int.from_bytes(sym[:32], "big") == 32 and int.from_bytes(sym[32:64], "big") == 4 and sym[64:68] == b"USDr", "Token symbol")
    check(word_address(hbytes(get(newer, "eth_getStorageAt", [SHARED, IMPL_SLOT, "latest"]), 32)) == IMPL, "Shared vault implementation address")
    for a in (DEDICATED, IMPL):
        check(get(newer, "eth_getCode", [a, "latest"]).lower() == contracts[a]["deployed_bytecode"].lower(), "Verified runtime matches RPC")

    deposit = load("usdr-recent")["items"][0]
    check(deposit["method"] == "depositWithAuthorization", "Newest direct USDr vault call category")
    shared = load("shared-recent")["items"][:2]
    check([x["method"] for x in shared] == ["transferV2"] * 2, "Newest direct shared vault calls category")
    candidates = {}
    windows = []
    nullifier = next(k for k, v in topic_names.items() if v == "Nullifier")
    for q, resp in selection:
        if q["method"] != "eth_getLogs":
            continue
        f = q["params"][0]
        lo, hi = (int(f[name], 16) for name in ("fromBlock", "toBlock"))
        check(f["address"] == DEDICATED and f["topics"] == [nullifier], "Selection filter")
        windows.append([lo, hi])
        for lg in resp["result"]:
            block = int(lg["blockNumber"], 16)
            check(lo <= block <= hi and lg["address"] == DEDICATED and lg["topics"][0] == nullifier, "Selection result")
            candidates[lg["transactionHash"]] = block
    check(len(candidates) == 5 and len(windows) == 6, "Range selection")
    shots = [(deposit, "usdr-deposit-new", selection, selection)]
    shots.extend((row, f"shared-send-{i}", checked, newer) for i, row in enumerate(shared, 1))
    for i, (h, height) in enumerate(sorted(candidates.items(), key=lambda x: x[1]), 1):
        stem = f"dedicated-nullifier-{i}"
        row = load(stem + "-tx")
        check(row["hash"] == h and row["block_number"] == height, "Explorer index selection")
        shots.append((row, stem, newer, newer))

    summary = []
    inclusion_inputs = {}
    for row, stem, batch, header_batch in shots:
        h, height = row["hash"], row["block_number"]
        tx = get(batch, "eth_getTransactionByHash", [h])
        receipt = get(batch, "eth_getTransactionReceipt", [h])
        block = get(header_batch, "eth_getBlockByNumber", [hex(height), False])
        check(int(block["number"], 16) == height, "Requested block number")
        check_inclusion(tx, receipt, block)
        inclusion_inputs[stem] = (tx, receipt, block)
        check(address(row["from"]) == address(tx["from"]) == address(receipt["from"]) == RELAY, "Outer caller")
        check(address(row["to"]) == address(tx["to"]) == address(receipt["to"]), "Outer target")
        check(row["raw_input"].lower() == tx["input"].lower(), "Explorer vs RPC calldata")
        time = timestamp(int(block["timestamp"], 16))
        check(datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")) == datetime.fromisoformat(time), "Time")
        check(row["status"] == "ok" and int(row["value"]) == int(tx["value"], 16) == 0, "Explorer status or native value")
        nodes = receipt["logs"]
        explorer = load(stem + "-logs")
        check(explorer.get("next_page_params") is None, "Explorer log page is incomplete")
        check(all(x["transaction_hash"] == h and x["block_number"] == height for x in explorer["items"]), "Explorer log references")
        check([raw_explorer(x) for x in sorted(explorer["items"], key=lambda l: l["index"])] == [raw_node(x) for x in nodes], "Explorer and RPC log bytes")
        check(all(x["transactionHash"] == h and x["blockHash"] == block["hash"] and not x["removed"] for x in nodes), "RPC log references")
        calls = call_path(tx, methods)
        check(all(allow is not True for _, _, allow in calls), "A subcall was allowed to fail")
        usdr_flows = [v for v in nodes if address(v["address"]) == USDR and v["topics"][0] == transfer]
        permissions = [v for v in nodes if address(v["address"]) == DEDICATED and topic_names.get(v["topics"][0]) == "PartialWithdrawal"]
        note_groups = {}
        event_counts = Counter()
        for _, emitter, topics, _ in map(raw_node, nodes):
            name = topic_names.get(topics[0])
            if name is not None:
                event_counts[name] += 1
            if name in ("Commitment", "EncryptedNote"):
                if name not in note_groups:
                    note_groups[name] = Counter()
                note_groups[name][(emitter, *topics[1:])] += 1
        for item, n in note_groups.get("EncryptedNote", {}).items():
            check(note_groups["Commitment"][item] == n == 1, "Encrypted note has no unique commitment on same emitter")
        check(event_counts["EncryptedNote"] > 0, "Missing encrypted note activity")
        if stem == "usdr-deposit-new":
            kind = "shield"
            check(calls == [(DEDICATED, "depositWithAuthorization", None)] and len(usdr_flows) == 1, "Public shield case")
            check(word_address(hbytes(usdr_flows[0]["topics"][2], 32)) == DEDICATED and not permissions, "Shield flow destination")
        elif permissions:
            kind = "unshield"
            check(len(usdr_flows) == len(permissions) == 1, "Public withdrawal corroboration")
            payout = usdr_flows[0]
            check(word_address(hbytes(payout["topics"][1], 32)) == DEDICATED, "Payout source is not the vault")
            check(payout["topics"][2] == permissions[0]["topics"][2] and payout["data"] == permissions[0]["data"], "Withdrawal transfer/amount cross-check")
        elif stem.startswith("shared-send"):
            kind = "shared-vault-spend"
            check(calls == [(SHARED, "transferV2", None)] and not usdr_flows, "Shared vault case")
        else:
            kind = "bundled-usdr-vault-spend"
            check((DEDICATED, "transferV2", False) in calls and (SHARED, "transferV2", False) in calls and not usdr_flows, "USDr bundle case")
        if kind.endswith("-spend"):
            check(not any(l["topics"][0] == transfer for l in nodes), "Spend emitted a public token Transfer event")
        amount = format_usdr(int(usdr_flows[0]["data"], 16)) if usdr_flows else None
        summary.append({"case": kind, "hash": h, "block": height, "utc": time, "native_value": 0,
                        "child_or_direct_calls": calls, "receipt_logs": len(nodes),
                        "encrypted_notes": event_counts["EncryptedNote"], "public_usdr": amount,
                        "transaction_root": block["transactionsRoot"], "receipt_root": block["receiptsRoot"],
                        "block_hash": block["hash"]})

    counts = Counter(row["case"] for row in summary)
    check(counts == {"shield": 1, "unshield": 2, "shared-vault-spend": 2, "bundled-usdr-vault-spend": 3}, "Study strata")
    for case, want in [("shield", ["10"]), ("unshield", ["0.2", "0.01"])]:
        check([v["public_usdr"] for v in summary if v["case"] == case] == want, "Published amounts")

    # Show that the two plausible shortcuts each misclassify all three public edges.
    false_positive_value = sum(r["native_value"] == 0 for r in summary if r["public_usdr"] is not None)
    false_positive_notes = sum(r["encrypted_notes"] > 0 for r in summary if r["public_usdr"] is not None)
    check(false_positive_value == false_positive_notes == 3, "Shortcuts did not fail on every edge case")

    # Nondestructive offline mutation of the raw receipt, one unit of test USDr precision.
    _, receipt, block = inclusion_inputs["usdr-deposit-new"]
    edited = deepcopy(receipt["logs"])
    i = next(i for i, l in enumerate(edited) if l["topics"][0] == transfer and l["address"] == USDR)
    edited[i]["data"] = "0x" + (int(edited[i]["data"], 16) + 1).to_bytes(32, "big").hex()
    forged, bloom = type_two_receipt(1, int(receipt["cumulativeGasUsed"], 16), edited)
    check(bloom == hbytes(receipt["logsBloom"], 256), "Control should preserve the log bloom")
    check(singleton_root(forged) != block["receiptsRoot"], "Edited amount failed to change receipt root")

    return {"chain_id": CHAIN_ID, "state_observation_block": int(anchor["number"], 16),
            "state_observation_time_utc": timestamp(int(anchor["timestamp"], 16)),
            "sample_counts": dict(counts), "selection_log_windows": windows, "cases": summary,
            "false_positive_value_zero": false_positive_value,
            "false_positive_encrypted_note_present": false_positive_notes,
            "one_base_unit_edit_changed_receipt_root": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print fully reconstructed results as JSON")
    args = parser.parse_args()
    result = verify()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        expected = json.loads((BASE / "results.json").read_bytes())
        check(json.loads(json.dumps(result)) == expected, "Rebuilt results differ from results.json")
        print("PASS: 8 testnet transactions, 8 transaction roots, 8 receipt roots, 8 header hashes.")
        print("PASS: raw RPC and Explorer logs, vault reads, 2 shortcut checks and 1 edited-receipt control.")


if __name__ == "__main__":
    main()
