import os
import binascii
import sys
from Crypto.Cipher import AES

game_key = b""

def ReadGameKey(filename):
    global game_key
    riffd = open(filename, "rb")
    riffd.seek(0x120)
    game_key = riffd.read(0x10)
    riffd.close()
def DecryptFile(filename):
    fd = open(filename, "rb")
    header = fd.read(4)
    if header != b"PSSE" and header != b"PSME":
        print(filename + " Not a PSSE File")
        exit()
    fd.seek(0x50, 0)
    enc1 = fd.read(0x20)
    fd.seek(0x70, 0)
    enc2 = fd.read(0x10)
    fd.seek(0x680, 0)
    file_data = fd.read()
    fd.close()

    iv = b"\x00\x01\x02\x03\04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
    key = b"\x4E\x29\x8B\x40\xF5\x31\xF4\x69\xD2\x1F\x75\xB1\x33\xC3\x07\xBE"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec1 = cipher.decrypt(enc1)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    iv2 = cipher.decrypt(enc2)

    cipher = AES.new(game_key, AES.MODE_CBC, iv2)
    game_data_dec = cipher.decrypt(file_data)
    return game_data_dec
    
    
file = sys.argv[1]

ReadGameKey(file+"\\RO\\License\\FAKE.RIF")
print("Reading Game key from FAKE.RIF: "+binascii.hexlify(game_key).decode("UTF-8"))
FileData = DecryptFile(file+"\\RO\\Application\\psse.list")
FilesList = FileData.replace(b"\r", b"").split(b"\n")

for File in FilesList:
    if File == b"":
        continue
    File = File.replace(b"/", b"\\")
    path = file.encode("UTF-8")
    FilePath = path+b"\\RO\\Application\\"+File
    print((b"Decrypting: "+FilePath).decode("UTF-8"))
    if os.path.exists(FilePath):
        FileData = DecryptFile(FilePath)
        open(FilePath, "wb").write(FileData)
    else:
        print("Error: File not Found")
    

open(file+"\\RO\\Application\\psse.list", "wb").write(FileData)
print("Done")