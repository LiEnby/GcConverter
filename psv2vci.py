import sys
import os
import hashlib
import struct
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

def verifyRifSig(key1, expectedSig):
    gotSig = deriveRifSignature(key1)
    
    if gotSig == expectedSig:
        return True
    else:
        return False

def verifyRifKey(key1, key2, expectedKey):
    gotKey = deriveRifKey(key1, key2)
    
    if gotKey == expectedKey:
        return True
    else:
        return False

def psv2vci(psv, keys, vci):
    # Read Key File
    print("Reading keyfile...")
    
    k = open(keys, "rb")
    key1 = k.read(0x20)
    key2 = k.read(0x20)
    k.close()

    # Read PSV Header
    p = open(psv, "rb")
    header = struct.unpack("3sxII32s20s32sQQ400x", p.read(SECTOR_SIZE))

    if header[0] == b"PSV" and header[1] == 0x1:
        # Get Rif Key and Rif Signature from PSV
        rifKey = header[3]
        rifSig = header[4]
        totalSize = header[6]
        totalSectors = int(totalSize / SECTOR_SIZE)
        # verify that the keyfile matches the rif key and signature.
        if verifyRifKey(key1, key2, rifKey) and verifyRifSig(key1, rifSig):
            print("Writing VCI ...")
            # Write VCI header
            v = open(vci, "wb")
            v.write(struct.pack("3sxIQ32s32s432x", b"VCI", 0x1, totalSize, key1, key2))
            
            # Write VCI Sectors
            for i in range(0, totalSectors):
                print("Writing sector "+str(i)+"/"+str(totalSectors)+"\r", end="")
                sector = p.read(SECTOR_SIZE)
                v.write(sector)
            
            v.close()
        else:
            print("Error: invalid key file.")
    else:
        print("Error: invalid PSV header")
    p.close()
    
    

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: <psvfile> <keyfile> [vcifile]")
        quit()
    # get psv filename
    psvFile = sys.argv[1]
    
    # get key file
    keyFile = sys.argv[2]

    # get output vci filename
    vciFile = None
    if len(sys.argv) >= 4:
        vciFile = sys.argv[3]
    else:
        vciFile = pathlib.Path(psvFile).stem + ".vci"
    
    # convert PSV to VCI
    psv2vci(psvFile, keyFile, vciFile)
    