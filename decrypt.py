import os
import binascii
import sys
import struct
import math
import hashlib

from Crypto.Cipher import AES
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import padding
    

game_key = b""
content_id = b""
original_iv = b""

psm_dev = False
file_size = 0
total_blocks = 0

def ReadGameKey(filename): # Read from FAKE.RIF
    global game_key
    global content_id
    
    riffd = open(filename, "rb")
    riffd.seek(0x50, 0)
    content_id = riffd.read(0x24)
    riffd.seek(0x120, 0)
    game_key = riffd.read(0x10)
    riffd.close()


def ReadPublisherKey(p12, khapp): # used for PSM Developer Assistant (debug PSSE)
    global game_key
    
    print("Reading PRIVATE KEY from "+p12)
    pkcs12_file = open(p12, 'rb').read() 
    passphrase = b"password" 
    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(pkcs12_file, passphrase) # Parse PKCS12 file
    
    print("Reading: HKAPP "+khapp)
    hkfd = open(khapp, "rb")
    offset_by = 0
    
    magic = hkfd.read(0x4) # is this an appkey or a keyring?
    if magic == b"PAKR":
        offset_by = 0x48 # Probably bad parsing, but whatever
    elif magic == b"PSHK":
        offset_by = 0
    else:
        print("Invalid khapp!")
    
    
    hkfd.seek(0x200+offset_by, 0)
    enc = hkfd.read(0x100)
    dec = private_key.decrypt(enc, padding.PKCS1v15()) # RSA Decrypt
    
    key = dec[0xC0:0xD0]
    iv = dec[0xD0:0xE0]
    
    hkfd.seek(0x80+offset_by, 0)
    ebuffer = hkfd.read(0x240)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(ebuffer) # AES Decrypt
    
    # Dont know what these are for.
    something1 = dec[0x00:0x10] 
    something2 = dec[0xA0:0xB0] 
    
    game_key = dec[0x60:0x70]
    
    hkfd.close()
    
    print("Game Key read from Publisher License Files: "+binascii.hexlify(game_key).decode("UTF-8"))
    
def IvRoll(location):
    iv_next = location
    iv = bytearray(original_iv)
    new_iv = bytearray(iv_next.to_bytes(0x10, "little"))
    for i in range(0,0x10):
        new_iv[i] ^= iv[i] 
    
    return bytes(new_iv)


def GetBlock(fd, block_id):
    global game_key
    global file_size
    global total_blocks
    current_iv = IvRoll(block_id)
    block_loc = block_id * 0x8000
    total_read = 0x8000
    trim_to = total_read
    
        
    if block_id == 0: # Skip to filedata
        block_loc = 0x680
        total_read -= 0x680
        trim_to = total_read
    elif block_loc % 0x80000 == 0: # Skip signature block
        block_loc += 0x400
        total_read -= 0x400
        trim_to = total_read
    
    rd_amt = ((block_loc - 0x680) - (0x400*math.floor(block_loc / 0x80000))) # Total amount of file read so far.
            
    if block_id >= total_blocks-1: # Is this the last block?
        total_read = file_size - rd_amt
        trim_to = total_read
        total_read += (0x10-(total_read % 0x10))
   
    if block_id > total_blocks-1:
        return b""
    if total_read <= 0:
        return b""
   
    fd.seek(block_loc, 0)

    file_data = fd.read(total_read)
    cipher = AES.new(game_key, AES.MODE_CBC, current_iv)
    return cipher.decrypt(file_data)[:trim_to]


def DecryptFile(input_filename):
    global game_key
    global content_id
    global original_iv
    global file_size
    global total_blocks
    global psm_dev

    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" # Header IV, used to find the real IV
    key = b"\x4E\x29\x8B\x40\xF5\x31\xF4\x69\xD2\x1F\x75\xB1\x33\xC3\x07\xBE" # Header key for PSM Runtime and used in all retail games.
    psm_dev_key = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF" # Header key for PSM Dev, used for all files encrypted with psm_encryptor.dll
    runtime_game_key = b"\xA8\x69\x3C\x4D\xF0\xAE\xED\xBC\x9A\xBF\xD8\x21\x36\x92\x91\x2D" # key for Sce.PlayStation.Core.dll

    total_blocks = math.floor(os.path.getsize(input_filename) / 0x8000)+1

    fd = open(input_filename, "rb")
    
    # Check magic is "PSSE" or "PSME"
    header = fd.read(4)
    if header != b"PSSE" and header != b"PSME":
        print("Not a valid PSSE File")
        exit()
    
    # Check PSSE Version is 0x1 (not sure what it would be otherwise)
    fd.seek(0x4, 0)
    version = struct.unpack('i', fd.read(4))[0]
    if version != 0x01:
        print("Unsupported version: "+str(version))
        exit()
    
    fd.seek(0x8, 0)
    file_size = struct.unpack('Q', fd.read(8))[0]
    
    fd.seek(0x10, 0)
    psse_type = struct.unpack('i', fd.read(4))[0]
    if psse_type != 0x1:
        print("Unknown PSSE Type: "+str(psse_type))
        exit()
    
    fd.seek(0x14, 0)
    read_content_id = fd.read(0x24)
    if read_content_id == b"IP9100-NPXS10074_00-0000000000000000": # Sce.PlayStation.Core.dll
        game_key = runtime_game_key
    elif read_content_id == (b"\x00"*0x24): # PSM developer assistant doenst include a Content ID
        psm_dev = True
    elif content_id != read_content_id:
        print("Content ID Mismatch! Expected: "+content_id.decode("UTF-8")+" but got"+read_content_id.decode("UTF-8"))
        exit()
    if game_key == b"":
        print("Unknown game key! if its debug PSSE, please provide publisher key (p12) and app seed (krng/hkapp) as seperate arguments")
        exit()
    
    fd.seek(0x40, 0)
    file_md5 = fd.read(0x10)
    
    # Supposadly this contains the filename.
    #fd.seek(0x50, 0)
    #enc1 = fd.read(0x20)
    #cipher = AES.new(key, AES.MODE_CBC, iv)
    #dec1 = cipher.decrypt(enc1)
    
    # Determine file IV
    fd.seek(0x70, 0)
    enc = fd.read(0x10)

    if psm_dev:
        key = psm_dev_key
        
    cipher = AES.new(key, AES.MODE_CBC, iv)
    original_iv = cipher.decrypt(enc)
    
    md5 = hashlib.md5()
    total_file_data = b""
    
    for i in range(0, total_blocks):
        file_block = GetBlock(fd, i)
        md5.update(file_block)
        total_file_data += file_block

    fd.close()
    
    total_file_data = total_file_data[:file_size] # trim to file_size
    
    got_md5 = md5.digest()
    if file_md5 != got_md5: # Verify decrypted file.
        print("MD5 Mismatch, Expected: "+binascii.hexlify(file_md5).decode("UTF-8")+" got: "+binascii.hexlify(got_md5).decode("UTF-8"))
        exit()
    
    return total_file_data
    

if len(sys.argv) <= 1:
    print("PSSE Decryptor by SilicaAndPina v2")
    print("(for retail games)     <PSM_GAME_FOLDER>")
    print("(for PSM Dev Packages) <PSM_GAME_FOLDER> <PSM_PUBLISHER_KEY> <PSM_HKAPP_OR_KRNG>")
    print("")
    print("For retail games, you require the RO/License/FAKE.RIF file")
    print("And for PSM Dev Packages, you need there original publisher key and keyring.")
    print("")
    print("This program expects the game files to be located in PSM_GAME_FOLDER/RO/Application")
    print("(just PSM_GAME_FOLDER/Application for PSM Developer Packages)")
    exit()
    
file = sys.argv[1]

if len(sys.argv) >= 4:
    psm_dev = True
    pkcs12name = sys.argv[2]
    khappname = sys.argv[3]
    print("Reading Publisher Key and App Key")
    
    if not os.path.exists(pkcs12name):
        print("Publisher Key not found")
        exit()
        
    if not os.path.exists(khappname):
        print("App key file not found.")
        exit()
        
    ReadPublisherKey(pkcs12name, khappname)

if os.path.isfile(file):
    print("Decrypting: "+file)
    data = DecryptFile(file)
    open(file, "wb").write(data)
    exit()

ro_path = b"/RO/Application/"
if psm_dev: # I guess for android this would also be true.
    ro_path = b"/Application/"

if not psm_dev: # When using PSM Dev, there are no licenses, instead keys are stored in krng or khapp file...
    license_file = os.path.normpath(file+"/RO/License/FAKE.RIF")
    if not os.path.exists(license_file):
        print("Cannot find license "+license_file)
        exit()
    
    ReadGameKey(license_file)
    print("Reading Game key from FAKE.RIF: "+binascii.hexlify(game_key).decode("UTF-8"))

psse_list = os.path.normpath(file.encode("UTF-8")+ro_path+b"psse.list")
    
if not os.path.exists(psse_list):
    print("Cannot find "+psse_list.decode("UTF-8"))
    exit()

file_data = DecryptFile(psse_list)
file_list = file_data.replace(b"\r", b"").split(b"\n")

for psse_file in file_list:
    if psse_file == b"":
        continue
    path = file.encode("UTF-8")
    file_path = os.path.normpath(path+ro_path+psse_file)
    print((b"Decrypting: "+file_path).decode("UTF-8"))
    if os.path.exists(file_path):
        decrypted_data = DecryptFile(file_path)
        open(file_path, "wb").write(decrypted_data)
    else:
        print("Error: File not Found")
    

open(psse_list, "wb").write(file_data)
print("Done")