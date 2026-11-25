"""Draw deterministic DAVID editorial SVGs from the saved analysis JSON.
Run --check to compare wording, layout, asset embedding and PNG dimensions.
"""
import argparse, base64, json, struct
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = json.loads((ROOT/'results.json').read_bytes())
EXTRA = json.loads((ROOT/'extensions.json').read_bytes())
PAPER='#f1f2f6'; WHITE='#fcfcff'; INK='#121219'; DARK='#181621'; DIM='#4e505e'
LAV='#bda5ff'; LITE='#eae1ff'; VIOLET='#5132c9'; LIME='#e5ff30'; LINE='#d5d6e1'
SANS='DejaVu Sans'; MONO='DejaVu Sans Mono'

class Page:
    def __init__(self, w, h, title, alt):
        self.w,self.h,self.nt = w,h,0
        self.parts=[f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-labelledby="title desc">',
            '<title id="title">'+escape(title)+'</title><desc id="desc">'+escape(alt)+'</desc>',
            '<defs><pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M40 0H0V40" stroke="#d5d6e1" stroke-width="1" fill="none" opacity=".75"/></pattern></defs>']
        self.rect(0,0,w,h,PAPER)
        self.rect(0,0,w,h,'url(#grid)')

    def rect(self,x,y,w,h,fill):
        self.parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{fill}"/>')

    def poly(self, pt, fill, stroke='none', sw=0):
        points=' '.join(f'{x},{y}' for x,y in pt)
        self.parts.append(f'<polygon points="{points}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>')

    def stroke(self,x1,y1,x2,y2,color=VIOLET,sw=3):
        self.parts.append(f'<path d="M{x1} {y1}L{x2} {y2}" fill="none" stroke="{color}" stroke-width="{sw}"/>')

    def txt(self, x, y, word, size, color=INK, weight=400, font=SANS, tracking=0, anchor='start'):
        self.nt += 1
        self.parts.append(f'<text id="t{self.nt}" x="{x}" y="{y}" fill="{color}" font-family="{font}" font-size="{size}" font-weight="{weight}" letter-spacing="{tracking}" text-anchor="{anchor}">{escape(word)}</text>')

    def lines(self,x,y,words,size,delta,color=INK,weight=400,font=SANS):
        for i,w in enumerate(words):self.txt(x,y+delta*i,w,size,color,weight,font)

    def cap(self, x, y, word, size=28, color=VIOLET):
        self.txt(x,y,word,size,color,700,MONO,2)

    def clipped(self,x,y,w,h,fill,stroke='none',sw=0,cut=26):
        self.poly([(x,y),(x+w-cut,y),(x+w,y+cut),(x+w,y+h),(x+cut,y+h),(x,y+h-cut)],fill,stroke,sw)

    def image(self, file,x,y,w,h):
        data=base64.b64encode((ROOT/'assets'/file).read_bytes()).decode('ascii')
        self.parts.append(f'<image x="{x}" y="{y}" width="{w}" height="{h}" preserveAspectRatio="xMidYMid meet" xlink:href="data:image/png;base64,{data}"/>')

    def paper_frame(self, series):
        self.poly([(1770,0),(2400,0),(2400,258),(2150,258),(1770,72)],LAV)
        self.poly([(0,1220),(180,1220),(358,1350),(0,1350)],LIME)
        self.stroke(48,65,72,65,DIM,2); self.stroke(60,53,60,77,DIM,2)
        self.cap(100,100,series,27)
        self.clipped(2186,38,149,149,INK,cut=18)
        self.image('rayls-mark-original.png',2201,53,119,119)

    def bottom(self, primary, secondary):
        self.clipped(100,1137,2200,124,INK)
        self.rect(131,1160,8,77,LIME)
        self.txt(160,1187,primary,41,WHITE,700)
        self.txt(160,1234,secondary,29,'#d9d4e9')
        self.stroke(100,1291,2300,1291,'#aeb0c0',2)
        self.cap(100,1328,'RAYLS ENYGMA PUBLIC   /   TESTNET PILOT',24)

    def output(self):return '\n'.join(self.parts+['</svg>','']).encode('utf-8')


def cover():
    p=Page(2500,1000,'Private payments. Auditable records.','Cover for the Rayls Enygma Public testnet study of public transaction records and restricted audit access.')
    p.poly([(1394,0),(2500,0),(2500,838),(2000,838),(1394,455)],LITE)
    p.poly([(1790,0),(2500,0),(2500,328),(2200,328)],LAV)
    p.poly([(0,926),(178,926),(300,1000),(0,1000)],LIME)
    p.stroke(50,73,76,73,DIM,2); p.stroke(63,61,63,85,DIM,2)
    p.cap(92,113,'ENYGMA PUBLIC  /  TESTNET PILOT',31)
    p.cap(94,183,'PUBLIC CHAIN RESEARCH',24,DIM)
    p.lines(84,330,['Private payments.','Auditable records.'],115,139,INK,700)
    p.rect(92,534,1060,7,VIOLET); p.rect(1152,534,146,7,LIME)
    p.lines(92,635,['See what the chain records.','Keep the details available for audit.'],48,68,DIM)
    p.clipped(92,766,1208,124,INK)
    p.rect(117,790,8,77,LIME)
    p.cap(144,819,f'{sum(DATA["sample_counts"].values())} PAYMENT-RELATED TRANSACTIONS',26,LIME)
    p.txt(144,864,f'{len(EXTRA["registry"]["samples"])} registry records checked against public data',34,WHITE,700)
    p.stroke(1450,178,1450,755,'#a594d8',2); p.stroke(1450,755,2336,755,'#a594d8',2)
    p.image('sealed-record-art.png',1423,137,950,632)
    for x,w,fill,label,color in [(1452,406,WHITE,'PUBLIC PROOF',VIOLET),(1880,458,INK,'AUDITOR RECORD',LIME)]:
        p.clipped(x,785,w,75,fill,VIOLET,2,cut=20); p.cap(x+25,833,label,25,color)
    p.clipped(2257,42,169,169,INK,cut=20)
    p.image('rayls-mark-original.png',2275,60,133,133)
    p.stroke(92,929,2410,929,'#aeb0c0',2)
    p.cap(92,969,'SHIELDED FROM THE PUBLIC, NOT FROM THE AUDITOR',25)
    p.cap(1998,969,'READ-ONLY TESTNET STUDY',23,DIM)
    return p


def receipts():
    n=sum(DATA['sample_counts'].values())
    mid=DATA['sample_counts']['shared-vault-spend']+DATA['sample_counts']['bundled-usdr-vault-spend']
    dep=next(row['public_usdr'] for row in DATA['cases'] if row['case']=='shield')
    exits=[row['public_usdr'] for row in DATA['cases'] if row['case']=='unshield']
    p=Page(2400,1350,'Same Value. Different records.','Observed public lines for one Rayls testnet deposit, two public withdrawals and five transactions with shielded spends.')
    p.paper_frame('01   /   WHAT THE EXPLORER CAN SHOW')
    p.txt(98,228,'Same Value. Different records.',90,INK,700)
    p.txt(100,313,f'All {n} sampled transactions showed native Value = 0.',43,DIM)
    cards=[(100,WHITE,VIOLET,INK,'01   SHIELD','1 TRANSACTION',f'{dep} test USDr',('Deposit amount visible.','Token Transfer into the vault.','Receipt also has an encrypted note.')),
           (847,INK,LIME,WHITE,'02   SHIELDED SPEND',f'{mid} TRANSACTIONS','No public Transfer',('Vault marks spent notes.','Outputs remain encrypted.','The payment amount is not listed.')),
           (1594,LITE,VIOLET,INK,'03   UNSHIELD','2 TRANSACTIONS',f'{exits[0]} and {exits[1]}',('Amounts in test USDr.','Recipient and amount visible.','Notes in the separate fee call.'))]
    for x,fill,tone,front,heading,cases,large,lines in cards:
        p.clipped(x+8,405,706,626,LAV,cut=30)
        p.clipped(x,396,706,626,fill,VIOLET,3,cut=30)
        p.rect(x+35,439,7,482,tone)
        p.cap(x+67,472,heading,28,tone)
        p.cap(x+67,550,cases,23,tone)
        p.txt(x+65,663,large,53 if x==847 else 62,front,700)
        p.stroke(x+68,713,x+649,713,tone,2)
        p.lines(x+66,795,lines,34,62,front)
    p.bottom('The token log answers the amount question.', 'Value = 0 and an encrypted note can also appear in a public deposit or exit.')
    return p


def vaults():
    path=next(s for s in EXTRA['call_paths'] if len(s['calls'])==2 and [c['method'] for c in s['calls']]==['transferV2','transferV2'])
    p=Page(2400,1350,'Same function. Two vaults.','One captured Multicall3 transaction in which two transferV2 subcalls target vaults with different public asset descriptions.')
    p.paper_frame('02   /   A MATCHED PAIR INSIDE ONE RECEIPT')
    p.txt(98,228,'Same function. Two vaults.',90,INK,700)
    p.txt(100,313,'Both calls execute inside the same captured Multicall3 transaction.',41,DIM)
    p.clipped(485,374,1430,155,INK,cut=31)
    p.txt(1200,432,f'BLOCK {path["block"]:,}  /  SINGLE BATCH',30,LIME,700,MONO,2,'middle')
    p.txt(1200,492,f'{path["hash"][:12]}…{path["hash"][-8:]}',36,WHITE,700,MONO,0,'middle')
    p.stroke(1200,530,1200,590,VIOLET,5)
    p.stroke(622,590,1777,590,VIOLET,5)
    for x in (622,1777):
        p.stroke(x,590,x,640,VIOLET,5); p.poly([(x-13,636),(x+13,636),(x,656)],VIOLET)
    for x,style,call,title,stat,detail in (
        (100,WHITE,path['calls'][0],'DEDICATED USDr VAULT','Getter: USDr','The vault identifies its asset.'),
        (1260,LITE,path['calls'][1],'SHARED VAULT','Getter: zero address','The sampled note logs do not name the token.')):
        p.clipped(x+8,669,1040,389,LAV,cut=30)
        p.clipped(x,660,1040,389,style,VIOLET,3,cut=30)
        p.cap(x+40,723,title,29)
        p.txt(x+39,817,'transferV2',62,INK,700,MONO)
        p.txt(x+991,810,f'…{call["target"][-6:]}',29,DIM,700,MONO,0,'end')
        p.stroke(x+40,850,x+998,850,VIOLET,2)
        p.txt(x+40,921,stat,45,INK,700)
        p.txt(x+41,990,detail,34,DIM)
    p.bottom('Read the target contract as well as the method name.', 'Vault asset settings were read after the sampled block. No private amount was decoded.')
    return p


def escrow():
    v=EXTRA['registry']; record=v['samples'][0]
    p=Page(2400,1350,'Audit access starts at registration.','Public registry key and envelope sizes verified from two testnet registrations, beside a separately labelled local synthetic key demonstration.')
    p.paper_frame('03   /   THE AUDITOR’S ENCRYPTED RECORD')
    p.txt(98,228,'Audit access starts at registration.',86,INK,700)
    p.txt(100,310,'Public registry evidence and a separate test with locally generated keys.',41,DIM)
    p.clipped(100,376,1320,674,WHITE,VIOLET,3,cut=30)
    p.cap(143,449,f'TESTNET REGISTRY  /  {len(v["samples"])} RECORDS',32)
    for y, label, value in [(547,'Auditor’s public key',v['auditor_public_key_bytes']),
                            (681,'ML-KEM capsule',record['kem_capsule_bytes']),
                            (815,'AES-GCM payload',record['encrypted_view_payload_bytes'])]:
        p.clipped(142,y-64,1236,106,LITE if y!=681 else PAPER,cut=15)
        p.txt(174,y+6,label,43,INK,700)
        p.txt(1335,y+9,f'{value:,} B',53,VIOLET,700,MONO,0,'end')
    p.txt(143,963,'Calldata, event and later storage reads matched.',38,INK,700)
    p.clipped(1473,376,827,674,INK,cut=32)
    p.cap(1516,449,'LOCAL KEY DEMO ONLY',29,LIME)
    p.lines(1516,548,['Matching key opens','the synthetic record.'],49,66,WHITE,700)
    p.stroke(1516,663,2258,663,'#655b7a',3)
    for i,t in enumerate(['Wrong key','Edited ciphertext','Swapped capsule']):
        y=738+i*88
        p.rect(1517,y-24,8,30,LAV); p.txt(1547,y,t,39,WHITE)
        p.txt(2255,y-2,'REJECTED',26,LIME,700,MONO,2,'end')
    p.bottom('Public access to ciphertext does not grant read access to its contents.', 'The local demo used no pilot keys or customer records.')
    return p


def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--check',action='store_true'); o=parser.parse_args()
    for name,fn in [('00-cover',cover),('01-public-receipts',receipts),('02-vault-pair',vaults),('03-auditor-envelope',escrow)]:
        f=fn(); svg=ROOT/'visuals'/f'{name}.svg'; png=svg.with_suffix('.png')
        if o.check:
            if svg.read_bytes()!=f.output():raise ValueError(f'{svg.name}: rebuilt vector differs')
            with png.open('rb') as s: top=s.read(24)
            if top[:16]!=b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' or struct.unpack('>II',top[16:24])!=(f.w,f.h):raise ValueError(f'{png.name}: unexpected image dimensions')
        else:svg.write_bytes(f.output())
    if o.check:print('PASS: rebuilt 4 evidence SVGs byte-for-byte; all 4 PNG dimensions match.')

if __name__=='__main__':main()
