import os
import binascii
import sys
import struct
import math
from Crypto.Cipher import AES

game_key = b""
content_id = b""
original_iv = b""

def IvRoll(location):
    iv_next = location
    iv = bytearray(original_iv)
    new_iv = bytearray(iv_next.to_bytes(0x10, "little"))
    for i in range(0,0x10):
        new_iv[i] ^= iv[i] 
    
    return bytes(new_iv)
    
def ReadGameKey(filename):
    global game_key
    global content_id
    
    riffd = open(filename, "rb")
    riffd.seek(0x50, 0)
    content_id = riffd.read(0x24)
    riffd.seek(0x120, 0)
    game_key = riffd.read(0x10)
    riffd.close()



def GetBlock(fd, blockNo):
    global game_key
    current_iv = IvRoll(blockNo)
    blockId = blockNo
    blockNo = blockNo * 0x8000
    total_read = 0x8000
    if blockId == 0: # Skip to filedata
        blockNo = 0x680
        total_read -= 0x680    
    elif blockNo % 0x80000 == 0: # Skip signature block
        blockNo += 0x400
        total_read -= 0x400
    fd.seek(blockNo, 0)

    file_data = fd.read(total_read)
    cipher = AES.new(game_key, AES.MODE_CBC, current_iv)
    return cipher.decrypt(file_data)

def DecryptFile(input_filename):
    global game_key
    global content_id
    global original_iv
    fd = open(input_filename, "rb")
    
    header = fd.read(4)
    if header != b"PSSE" and header != b"PSME":
        print("Not a valid PSSE File")
        exit()
        
    fd.seek(0x4, 0)
    version = struct.unpack('i', fd.read(4))[0]
    if version != 0x01:
        print("Unsupported version: "+str(version))
        exit()
    
    fd.seek(0x8, 0)
    size = struct.unpack('i', fd.read(4))[0]
    totalBlocks = math.ceil(size/0x8000)+1
    
    fd.seek(0x14, 0)
    read_content_id = fd.read(0x24)
    if read_content_id == b"IP9100-NPXS10074_00-0000000000000000": #Runtime Files
        game_key = b"\xA8\x69\x3C\x4D\xF0\xAE\xED\xBC\x9A\xBF\xD8\x21\x36\x92\x91\x2D"
    elif content_id != read_content_id:
        print("Content ID Mismatch! Expected: "+content_id.decode("UTF-8")+" but got"+read_content_id.decode("UTF-8"))
        
    #not sure what this part is for
    #fd.seek(0x50, 0)
    #enc1 = fd.read(0x20)
    
    #iv
    fd.seek(0x70, 0)
    enc2 = fd.read(0x10)

    iv = b"\x00\x01\x02\x03\04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
    key = b"\x4E\x29\x8B\x40\xF5\x31\xF4\x69\xD2\x1F\x75\xB1\x33\xC3\x07\xBE"
    #cipher = AES.new(key, AES.MODE_CBC, iv)
    #dec1 = cipher.decrypt(enc1)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    original_iv = cipher.decrypt(enc2)
    
    total_file_data = b""
    for i in range(0,totalBlocks):
        total_file_data += GetBlock(fd, i)
        
    fd.close()
    

    return total_file_data[:size] # trim to sz
    

if len(sys.argv) <= 1:
    print("PSSE Decryptor by SilicaAndPina")
    print("Usage: decrypt.py <PSM_GAME_FOLDER>")
    print("Where the game folder contains \"RO/License/FAKE.RIF\" and \"RO/Application/psse.list\"")
    exit()
    
file = sys.argv[1]

if os.path.isfile(file):
    print("Decrypting: "+file)
    data = DecryptFile(file)
    open(file, "wb").write(data)
    exit()
    
licenseFile = os.path.normpath(file+"/RO/License/FAKE.RIF")
if not os.path.exists(licenseFile):
    print("Cannot find license "+licenseFile)
    exit()
    
ReadGameKey(licenseFile)
print("Reading Game key from FAKE.RIF: "+binascii.hexlify(game_key).decode("UTF-8"))

psseList = os.path.normpath(file+"/RO/Application/psse.list")
if not os.path.exists(psseList):
    print("Cannot find "+psseList)
    exit()

FileData = DecryptFile(psseList)
FilesList = FileData.replace(b"\r", b"").split(b"\n")

for File in FilesList:
    if File == b"":
        continue
    path = file.encode("UTF-8")
    FilePath = os.path.normpath(path+b"/RO/Application/"+File)
    print((b"Decrypting: "+FilePath).decode("UTF-8"))
    if os.path.exists(FilePath):
        DecryptedData = DecryptFile(FilePath)
        open(FilePath, "wb").write(DecryptedData)
    else:
        print("Error: File not Found")
    

open(psseList, "wb").write(FileData)
print("Done")
