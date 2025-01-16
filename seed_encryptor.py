#!/usr/bin/env python3

import os,sys,brotli,base36,getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

def load_bip39(p="english.txt"):
    with open(p,encoding="utf-8") as f:
        w=[x.strip() for x in f]
    if len(w)!=2048: raise ValueError("Invalid BIP39")
    return {v:i for i,v in enumerate(w)},w

def kdf(pw,s,l=32):
    return Scrypt(salt=s,length=l,n=2**15,r=8,p=1,backend=default_backend()).derive(pw.encode())

def to_bits(v,n):
    return [(v>>i)&1 for i in range(n)][::-1]

def from_bits(b):
    x=0
    for bit in b: x=(x<<1)|bit
    return x

def pack_words(ws,b2i):
    bits=[]
    for w in ws:
        if w in b2i:
            bits.append(0)
            bits+=to_bits(b2i[w],11)
        else:
            print(f"Warning: {w} not in BIP39",file=sys.stderr)
            bits.append(1)
            b=w.encode()
            ln=len(b)
            bits+=to_bits(ln,16)
            for byte in b: bits+=to_bits(byte,8)
    while len(bits)%8: bits.append(0)
    r=bytearray()
    for i in range(0,len(bits),8):
        r.append(from_bits(bits[i:i+8]))
    return r

def unpack_words(data,i2b):
    bits=[]
    for b in data:
        bits+=to_bits(b,8)
    ws=[]
    i=0
    while i<len(bits):
        mode=bits[i]; i+=1
        if mode==0:
            if i+11>len(bits): break
            idx=from_bits(bits[i:i+11])
            i+=11
            if idx<0 or idx>=2048: break
            ws.append(i2b[idx])
        else:
            if i+16>len(bits): break
            ln=from_bits(bits[i:i+16])
            i+=16
            if i+8*ln>len(bits): break
            bb=[]
            for _ in range(ln):
                bb.append(from_bits(bits[i:i+8]))
                i+=8
            ws.append(bytearray(bb).decode())
    return ws

def encrypt_data(ws,pw,b2i):
    if not ws: return ""
    raw=pack_words(ws,b2i)
    c=brotli.compress(raw)
    s=os.urandom(8)
    n=os.urandom(12)
    key=kdf(pw,s)
    ct=AESGCM(key).encrypt(n,c,None)
    return base36.dumps(int.from_bytes(s+n+ct,"big"))

def decrypt_data(enc,pw,i2b):
    if not enc: return []
    v=base36.loads(enc)
    bl=(v.bit_length()+7)//8
    p=v.to_bytes(bl,"big")
    if len(p)<20: raise ValueError("Bad data")
    s,n,ct=p[:8],p[8:20],p[20:]
    key=kdf(pw,s)
    d=AESGCM(key).decrypt(n,ct,None)
    return unpack_words(brotli.decompress(d),i2b)

def main():
    b2i,i2b=load_bip39()
    m=input("Encrypt or Decrypt? [E/D]: ").lower()
    if m not in["e","encrypt","d","decrypt"]: sys.exit("Invalid")
    pw=getpass.getpass("Password: ")
    if m.startswith("e"):
        ws=input("Enter words: ").split()
        try: print("\n"+encrypt_data(ws,pw,b2i))
        except Exception as e: sys.exit(f"Error: {e}")
    else:
        enc=input("Base36 ciphertext: ")
        try: print("\n"+" ".join(decrypt_data(enc,pw,i2b)))
        except Exception as e: sys.exit(f"Error: {e}")

if __name__=="__main__":
    main()
