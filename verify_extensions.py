#!/usr/bin/env python3
"""Trace public call paths and the registered audit envelopes, offline."""
import argparse
import json
from collections import Counter
from datetime import datetime

from encoding import address, check, digest, hbytes, hash_header, word_address
from verify import (BASE, CHAIN_ID, DEDICATED, IMPL_SLOT, MULTICALL, SHARED,
                    abi_signature, check_inclusion, event_topic, get, load,
                    pair_batch, raw_explorer, raw_node, selector, timestamp)

REGISTRY = '0xa473291ffb33e2276f364fae169f03c4406719e9'
REG_IMPL = '0x9686a3d5a9fd2101d15888c6a09a64fafa7ee349'
FORWARDER = '0x12b6640048deb2e8ffda4bc10bb2a640b70eca6d'
RLS_VAULT = '0x97b5d78dbe06d8c8c843f87b5aa2d8587b890795'


class ABI:
    def __init__(self, data):
        self.data = data

    def word(self, i):
        check(i >= 0 and i % 32 == 0 and i + 32 <= len(self.data), 'ABI word out of bounds')
        return self.data[i:i+32]

    def num(self, i):
        return int.from_bytes(self.word(i), 'big')

    def ptr(self, i, base=0):
        pos = base + self.num(i)
        self.word(pos)
        return pos

    def blob(self, pos):
        sz = self.num(pos)
        start = pos + 32
        pad = (sz + 31) // 32 * 32
        check(start + pad <= len(self.data) and not any(self.data[start+sz:start+pad]), 'ABI bytes length or padding')
        return self.data[start:start+sz]

    def array(self, pos):
        count = self.num(pos)
        start = pos + 32
        check(count <= (len(self.data) - start)//32, 'ABI array length')
        return range(start, start+32*count, 32)

    def bytes_array(self, pos):
        return [self.blob(self.ptr(i, pos+32)) for i in self.array(pos)]


def recorded_batch(stem):
    qs = {x['id']:x for x in load(stem+'_request')}
    rs = {x['id']:x for x in load(stem)}
    check(qs.keys() == rs.keys(), 'Registry RPC IDs')
    return [(qs[k], rs[k]) for k in sorted(qs)]


def bind_latest(pairs):
    check(int(get(pairs, 'eth_chainId', []), 16) == CHAIN_ID, 'Extension network ID')
    a, b = (get(pairs, 'eth_getBlockByNumber', ['latest', False], i) for i in (0, 1))
    check(a == b and hash_header(a) == a['hash'], 'Latest state sample moved or failed header check')
    return (int(a['number'], 16), timestamp(int(a['timestamp'], 16)))


def children(tx):
    target = address(tx['to'])
    data = hbytes(tx['input'])
    if target != MULTICALL:
        return [(target, data)]
    check('0x'+data[:4].hex() == selector('aggregate3((address,bool,bytes)[])'), 'Batch selector')
    abi = ABI(data[4:])
    array = abi.ptr(0)
    out=[]
    for i in abi.array(array):
        start = abi.ptr(i, array+32)
        check(abi.num(start+32) == 0, 'A reviewed subcall permitted failure')
        out.append((word_address(abi.word(start)), abi.blob(abi.ptr(start+64,start))))
    return out


def forwarded(data, execute):
    check('0x'+data[:4].hex() == execute, 'Forwarder selector')
    abi = ABI(data[4:]); pos=abi.ptr(0)
    return word_address(abi.word(pos)), word_address(abi.word(pos+32)), abi.blob(abi.ptr(pos+192,pos))


def decode_transfer(data, target):
    abi = ABI(data[4:]); pos = abi.ptr(0)
    st = abi.ptr(pos+8*32,pos)
    statement=[abi.num(i) for i in abi.array(st)]
    nin, nout=abi.num(pos+9*32),abi.num(pos+10*32)
    left=abi.bytes_array(abi.ptr(32)); right=abi.bytes_array(abi.ptr(64))
    start=1+3*nin
    end=start+nout
    # The three-output calls in this corpus have one extra public word.
    check(nout == len(left) == len(right) and nout in (2,3) and nin > 0 and len(statement) == end+2+(nout==3), 'Structured proof statement bounds')
    check(statement[0]==0 and statement[end]==int(target,16),'Payment message or proof vault target')
    outputs=list(zip(statement[start:end],left,right))
    return list(zip(statement[1:1+nin],statement[1+2*nin:1+3*nin])), outputs


def check_calls(data, logs, target):
    inputs, outputs = decode_transfer(data, target)
    seen_inputs = []
    seen_outputs = []
    for event in logs:
        topics=[t.lower() for t in event['topics']]
        if topics[0] == event_topic('Nullifier(uint256,uint256,uint256)'):
            seen_inputs.append((int(topics[2],16),int(topics[3],16)))
        if topics[0] == event_topic('EncryptedNote(uint256,uint256,bytes,bytes)'):
            abi = ABI(hbytes(event['data']))
            seen_outputs.append((int(topics[2],16),abi.blob(abi.ptr(0)),abi.blob(abi.ptr(32))))
    check(inputs == seen_inputs, 'Input nullifiers differ from raw logs')
    check(outputs == seen_outputs, 'Output notes disagree with calldata')
    return {'inputs':len(inputs),'outputs':len(outputs),'ciphertext_sizes':sorted({(len(a),len(b)) for _,a,b in outputs})}


def forward_log_matches(receipt, account, target):
    topic=event_topic('Relayed(address,address,uint256,address,uint256)')
    logs=[l for l in receipt['logs'] if address(l['address']) == FORWARDER and l['topics'][0] == topic]
    check(len(logs)==1,'Expected one forwarder event')
    check([word_address(hbytes(t,32)) for t in logs[0]['topics'][1:3]]==[account,target], 'Forwarder event account or target')


def verify_paths(abi, base):
    methods = {}
    for x in (*load('verified-contracts').values(),*abi.values()):
        for f in x.get('abi_subset',x.get('abi')):
            if f['type']=='function':methods[selector(abi_signature(f))] = f['name']
    execute=next(k for k,v in methods.items() if v=='execute')
    transfer=next(k for k,v in methods.items() if v=='transferV2')
    batches = [pair_batch(k) for k in ('check-rpc','selector-rpc','audit-rpc')]
    txs = {r['result']['hash']:r['result'] for batch in batches for q,r in batch if q['method']=='eth_getTransactionByHash' and r.get('result')}
    receipts = {r['result']['transactionHash']:r['result'] for batch in batches for q,r in batch if q['method']=='eth_getTransactionReceipt' and r.get('result')}
    found=Counter()
    all_calls=[]
    for row in base['cases']:
        h=row['hash']; tx=txs[h]; receipt=receipts[h]
        paths=[]
        for to, data in children(tx):
            op = '0x'+data[:4].hex()
            details={'target':to,'selector':op,'method':methods[op]}
            if op == transfer:
                check(to in (DEDICATED,SHARED,RLS_VAULT),'Unexpected vault in transfer')
                check(sum(1 for a,_ in children(tx) if a==to)==1,'Ambiguous logs from multiple calls to same vault')
                details.update(check_calls(data,[l for l in receipt['logs'] if address(l['address'])==to],to))
                found['shielded_calls']+=1
                found['output_notes']+=details['outputs']
            elif to==FORWARDER:
                account, dest, inner = forwarded(data,execute)
                inner_sel='0x'+inner[:4].hex()
                check(dest==DEDICATED and row['case']=='unshield' and methods[inner_sel] in ('partialWithdraw','partialWithdrawWithRelayerFee'), 'Unexpected forwarded exit')
                forward_log_matches(receipt,account,dest)
                l=next(l for l in receipt['logs'] if l['topics'][0]==event_topic('PartialWithdrawal(uint256,address,uint256,uint256)'))
                check(address(l['address']) == dest and int(l['data'],16) > 0,'Forwarded exit did not emit vault payout')
                inner_abi=ABI(inner[4:]); inner_items=next(f['inputs'] for f in load('verified-contracts')[DEDICATED]['abi_subset'] if f.get('name')==methods[inner_sel]);
                # The first element of withdrawParams is the public amount; the second ABI parameter is the recipient.
                check([x['type'] for x in inner_items[:3]] == ['uint256[]','address','tuple'], 'Public-exit ABI head')
                params=inner_abi.array(inner_abi.ptr(0))
                check(len(params)>0 and word_address(inner_abi.word(32))==word_address(hbytes(l['topics'][2],32)) and inner_abi.num(params[0])==int(l['data'],16),'Inner withdrawal inputs do not match event')
                details.update({'forwarded_to':dest,'forwarded_method':methods[inner_sel]})
                found['forwarded_exits']+=1
            paths.append(details)
        all_calls.append({'hash':h,'block':row['block'],'calls':paths})
    check(found == {'shielded_calls':12,'output_notes':26,'forwarded_exits':2},'Expanded sample totals')
    return dict(found),all_calls


def verify_registrations(verified):
    probe=recorded_batch('registry_probe_rpc')
    recheck=recorded_batch('registry_recheck_rpc')
    runtime_height,runtime_utc=bind_latest(probe); state_height,state_utc=bind_latest(recheck)
    check(word_address(hbytes(get(probe,'eth_getStorageAt',[REGISTRY,IMPL_SLOT,'latest']),32))==REG_IMPL,'UserRegistry implementation')
    for x in (REG_IMPL,FORWARDER):
        check(verified[x]['verified'] and get(probe,'eth_getCode',[x,'latest']).lower()==verified[x]['runtime'].lower(),'Verified registry or forwarder runtime')
    fs={x['name']:abi_signature(x) for x in verified[REG_IMPL]['abi']}
    execute=selector(next(abi_signature(x) for x in verified[FORWARDER]['abi'] if x['name']=='execute'))
    topic=event_topic(fs['UserRegistered'])
    config = load('pilot-app-config')
    check(address(config['embedded_proxy'])==REGISTRY,'Pilot registry from public app configuration')
    def latest(method, who=''):
        return hbytes(get(recheck,'eth_call',[{'to':REGISTRY,'data':selector(fs[method])+who},'latest']))
    pub=ABI(latest('auditorPublicKey')); key = pub.blob(pub.ptr(0))
    check(len(key)==1184 and digest(key)==config['embedded_auditor_key_keccak'],'Public auditor key length and fingerprint')
    log_index={}
    windows=[]
    for q,r in probe:
        if q['method']!='eth_getLogs':continue
        args=q['params'][0]; a,b=int(args['fromBlock'],16),int(args['toBlock'],16)
        check(address(args['address'])==REGISTRY and args['topics']==[topic],'Unexpected registration selection filter')
        windows.append([a,b])
        for l in r['result']:
            check(address(l['address'])==REGISTRY and l['topics'][0]==topic and a<=int(l['blockNumber'],16)<=b,'Invalid registry range match')
            log_index[l['transactionHash']]=l
    check(len(log_index)==2 and len(windows)==6,'Registration sample counts')
    samples=[]
    for i, (txhash, search) in enumerate(sorted(log_index.items(),key=lambda v:int(v[1]['blockNumber'],16)),1):
        tag=search['blockNumber']; tx=get(recheck,'eth_getTransactionByHash',[txhash]); receipt=get(recheck,'eth_getTransactionReceipt',[txhash]); header=get(recheck,'eth_getBlockByNumber',[tag,False]); check_inclusion(tx,receipt,header)
        check(address(tx['to'])==FORWARDER and int(tx['value'],16)==0,'Expected relayed registration')
        explored=load(f'registration-{i}-tx'); logs=load(f'registration-{i}-logs')
        check(explored['hash']==txhash and explored['block_number']==int(tag,16) and explored['raw_input'].lower()==tx['input'].lower(),'Explorer registration transaction')
        check(logs.get('next_page_params') is None and [raw_explorer(x) for x in logs['items']]==[raw_node(x) for x in receipt['logs']],'Explorer registry logs')
        event=next(l for l in receipt['logs'] if l['topics'][0]==topic and address(l['address'])==REGISTRY)
        check(raw_node(search)==raw_node(event) and search['transactionHash']==event['transactionHash'],'Indexed registration vs receipt')
        account, target, inner = forwarded(hbytes(tx['input']),execute)
        check(target==REGISTRY and account==word_address(hbytes(event['topics'][1],32)),'Registration emitter and forwarded account')
        forward_log_matches(receipt,account,REGISTRY)
        check('0x'+inner[:4].hex()==selector(fs['register']),'Forwarded register selector')
        inp=ABI(inner[4:]); ev=ABI(hbytes(event['data'])); padding='0'*24+account[2:]
        pk=ABI(latest('getKeys',padding)); esc=ABI(latest('getAuditCiphertexts',padding))
        check(int.from_bytes(latest('isRegistered',padding),'big')==1,'Registered account lookup')
        check(inp.word(0)==ev.word(0)==pk.word(0),'Public spend-key mismatch')
        fields=[inp.blob(inp.ptr(x)) for x in (32,64,96)]
        check(fields==[ev.blob(ev.ptr(x)) for x in (32,64,96)],'Registration calldata/event mismatch')
        check(fields==[pk.blob(pk.ptr(32)),esc.blob(esc.ptr(0)),esc.blob(esc.ptr(32))],'Latest registry read and public registration mismatch')
        check([len(x) for x in fields]==[1184,1088,92],'Audit envelope field sizes')
        old = next(r for q,r in recheck if q['method']=='eth_call' and q['params']==[{'to':REGISTRY,'data':selector(fs['getAuditCiphertexts'])+padding},tag])
        check('pruned' in old.get('error',{}).get('message',''),'Historic state scope changed')
        when=timestamp(int(header['timestamp'],16))
        check(datetime.fromisoformat(when)==datetime.fromisoformat(explored['timestamp'].replace('Z','+00:00')),'Registration time')
        samples.append({'hash':txhash,'block':int(tag,16),'utc':when,'view_public_key_bytes':len(fields[0]),'kem_capsule_bytes':len(fields[1]),'encrypted_view_payload_bytes':len(fields[2]),'matches_calldata_event_and_latest_getters':True,'historic_state':'pruned'})
    return {'registry':REGISTRY,'runtime_observation_block':runtime_height,'runtime_observation_utc':runtime_utc,'getter_observation_block':state_height,'getter_observation_utc':state_utc,'auditor_public_key_bytes':len(key),'auditor_public_key_keccak':digest(key),'selection_log_windows':windows,'samples':samples}


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--json',action='store_true')
    cmd=cli.parse_args()
    abi=load('registry-abis'); old=json.loads((BASE/'results.json').read_bytes())
    counts, paths=verify_paths(abi,old)
    result={'expanded_transfer_checks':counts,'call_paths':paths,'registry':verify_registrations(abi)}
    if cmd.json:print(json.dumps(result,indent=2))
    else:
        check(json.loads(json.dumps(result))==json.loads((BASE/'extensions.json').read_bytes()),'Reconstructed follow-up results differ')
        print('PASS: 12 transferV2 subcalls matched their nullifiers and 26 encrypted output notes; 2 forwarded public exits decoded.')
        print('PASS: 2 registration receipts, their committed roots and matching registry envelope fields; pilot auditor-key fingerprint.')


if __name__=='__main__':main()
