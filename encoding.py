"""Reused Ethereum encoding helpers from DAVID's TokenOne evidence study.
Used to re-encode the saved type-2 transactions, receipts and block headers.
"""
import re

MASK64 = (1 << 64) - 1
ROT = (0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14)
RC = (0x1,0x8082,0x800000000000808A,0x8000000080008000,0x808B,0x80000001,
      0x8000000080008081,0x8000000000008009,0x8A,0x88,0x80008009,0x8000000A,
      0x8000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
      0x8000000000008002,0x8000000000000080,0x800A,0x800000008000000A,
      0x8000000080008081,0x8000000000008080,0x80000001,0x8000000080008008)


def check(condition, label):
    if not condition:
        raise ValueError(label)


def rol(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK64


def keccak256(data):
    """Ethereum's Keccak-256 (0x01 suffix), not FIPS SHA3-256."""
    rate = 136
    p = bytearray(data) + bytearray([1])
    p += b"\0" * ((-len(p)) % rate)
    p[-1] |= 0x80
    a = [0] * 25
    for start in range(0, len(p), rate):
        for i in range(rate // 8):
            a[i] ^= int.from_bytes(p[start+8*i:start+8*i+8], "little")
        for rc in RC:
            c = [a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20] for x in range(5)]
            d = [c[(x-1)%5] ^ rol(c[(x+1)%5], 1) for x in range(5)]
            b = [0] * 25
            for y in range(5):
                for x in range(5):
                    i = x + 5*y
                    b[y + 5*((2*x+3*y)%5)] = rol(a[i] ^ d[x], ROT[i])
            for y in range(5):
                for x in range(5):
                    a[x+5*y] = b[x+5*y] ^ ((~b[(x+1)%5+5*y]) & b[(x+2)%5+5*y])
            a[0] ^= rc
    return b"".join(x.to_bytes(8,"little") for x in a[:4])


def hbytes(x, length=None):
    check(isinstance(x,str) and re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*",x),"malformed hex")
    data = bytes.fromhex(x[2:])
    if length is not None:
        check(len(data) == length, "unexpected hex length")
    return data


def address(x):
    if isinstance(x, dict):
        x = x["hash"]
    return "0x" + hbytes(x,20).hex()


def word_address(data):
    check(len(data) == 32 and data[:12] == bytes(12), "address padding")
    return "0x" + data[12:].hex()



BASE_FIELDS=(
    ("parentHash",32),("sha3Uncles",32),("miner",20),("stateRoot",32),
    ("transactionsRoot",32),("receiptsRoot",32),("logsBloom",256),("difficulty",None),
    ("number",None),("gasLimit",None),("gasUsed",None),("timestamp",None),
    ("extraData",0),("mixHash",32),("nonce",8)
)
OPTIONAL_FIELDS=(
    ("baseFeePerGas",None),("withdrawalsRoot",32),("blobGasUsed",None),("excessBlobGas",None),
    ("parentBeaconBlockRoot",32),("requestsHash",32)
)


def integer(x):
    return int(x,16)


def rlp(item):
    """Canonical RLP for bytes, nonnegative integers and lists."""
    if isinstance(item,int):
        check(item>=0,"integer must be nonnegative")
        return rlp(item.to_bytes((item.bit_length()+7)//8,"big"))
    if isinstance(item,bytes):
        if len(item)==1 and item[0]<128:
            return item
        return prefix(item,128)
    return prefix(b"".join(rlp(x) for x in item),192)


def prefix(payload,offset):
    size=len(payload)
    if size<56:
        return bytes([offset+size])+payload
    n=size.to_bytes((size.bit_length()+7)//8,"big")
    return bytes([offset+55+len(n)])+n+payload


def digest(raw):
    return "0x"+keccak256(raw).hex()


def singleton_root(value):
    # The sole owner's key is RLP(0) = 0x80, an even, terminal nibble path.
    path=bytes([0x20])+rlp(0)
    return digest(rlp([path,value]))


def signed_type_two(tx):
    check(integer(tx["type"])==2 and tx.get("to"),"Not a type-2 contract call")
    parity=integer(tx.get("yParity",tx["v"]))
    check(parity in (0,1),"Invalid signing parity")
    l=[(hbytes(e["address"],20), [hbytes(k,32) for k in e["storageKeys"]]) for e in tx["accessList"]]
    fields=[integer(tx[k]) for k in ("chainId","nonce","maxPriorityFeePerGas","maxFeePerGas","gas")]
    return bytes([2])+rlp(fields+[hbytes(tx["to"],20),integer(tx["value"]),hbytes(tx["input"]),l,
                                parity,integer(tx["r"]),integer(tx["s"])])


def event_bytes(log):
    a=hbytes(address(log["address"]),20)
    topics=[hbytes(t,32) for t in log["topics"] if t is not None]
    return [a,topics,hbytes(log["data"])]


def events_bloom(events):
    bits=0
    for a,topics,_ in events:
        for item in [a,*topics]:
            d=keccak256(item)
            for i in (0,2,4):
                bits|=1<<(int.from_bytes(d[i:i+2],"big")&2047)
    return bits.to_bytes(256,"big")


def type_two_receipt(status,cumulative_gas,rawlogs):
    check(status in (0,1),"Invalid receipt execution status")
    events=[event_bytes(l) for l in rawlogs]
    bloom=events_bloom(events)
    return bytes([2])+rlp([status,cumulative_gas,bloom,events]),bloom


def hash_header(b):
    seen_absent=False
    fields=[]
    for k,sz in BASE_FIELDS:
        fields.append(integer(b[k]) if sz is None else hbytes(b[k],sz or None))
    for k,sz in OPTIONAL_FIELDS:
        if b.get(k) is None:
            seen_absent=True
            continue
        check(not seen_absent,"Header optional layout is not a contiguous suffix")
        fields.append(integer(b[k]) if sz is None else hbytes(b[k],sz))
    return digest(rlp(fields))
