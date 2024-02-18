import os
import sys
import struct
import hashlib
import binascii
import pathlib

SECTOR_SIZE = 0x200

def deriveRifKey(key1, key2):
    # sha256 hash key1 + key2 = rif key
    m = hashlib.sha256()
    m.update(key1)
    m.update(key2)
    return m.digest()

def deriveRifSignature(key1):
    # sha1 hash of key1 = rif signature
    m = hashlib.sha1()
    m.update(key1)
    return m.digest()
    
def vci2psv(vci, psv):
    keyFile = pathlib.Path(psv).stem + "-keys.bin"

    v = open(vci, "rb")
    print("Reading VCI file ...")
    header = struct.unpack("3sxIQ32s32s432x", v.read(SECTOR_SIZE))
    
    if header[0] == b"VCI" and header[1] == 0x1:
        totalSize = header[2]
        totalSectors = int(totalSize / SECTOR_SIZE)
        
        print("Deriving keys ...")
        
        # derive rif key from original key parts
        key = deriveRifKey(header[3], header[4])
        print("Rif Key: "+binascii.hexlify(key).decode("UTF-8"))
            
        # derive rif signature from key parts
        sig = deriveRifSignature(header[3])
        print("Rif Signature: "+binascii.hexlify(sig).decode("UTF-8"))
        
        # write key parts to a file
        k = open(keyFile, "wb")
        print("Writing key parts to: \""+keyFile+"\" ...")

        k.write(header[3])
        k.write(header[4])
        k.close()
         
        p = open(psv, "wb")
        print("Writing PSV file ...")
        
        # write PSV header
        p.write(struct.pack("3sxII32s20s32sQQ400x", b"PSV", 0x1, 0, key, sig, b"\x00"*0x20, totalSize, 1))
        
        # write all sectors to PSV
        m = hashlib.sha256()        
        for i in range(0, totalSectors):
            print("Writing sector "+str(i)+"/"+str(totalSectors)+"\r", end="")
            sector = v.read(SECTOR_SIZE)
            m.update(sector)
            p.write(sector)
        
        # write psv data hash to PSV
        p.seek(0x40, os.SEEK_SET)
        p.write(m.digest())
        
        p.close()
    else:
        print("VCI Header is invalid.")
    v.close()
    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: [vcifile] [psvfile]")
        quit()
    vciFile = sys.argv[1]
    psvFile = sys.argv[2]
    vci2psv(vciFile, psvFile)