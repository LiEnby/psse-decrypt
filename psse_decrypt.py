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
    print("[*] Reading PRIVATE KEY from "+p12)
    pkcs12_file = open(p12, 'rb').read() 
    passphrase = b"password" 
    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(pkcs12_file, passphrase) # Parse PKCS12 file
    
    print("[*] Reading HKAPP "+khapp)
    hkfd = open(khapp, "rb")
    offset_by = 0
    
    magic = hkfd.read(0x4) 
    if magic == b"PAKR": # Keyring
        offset_by = 0x48 
    elif magic == b"tkdb": # Protected_kconsole.dat- needs more research
        offset_by = 0x10
    elif magic == b"PSHK": # Raw HKAPP
        offset_by = 0
    else:
        print("[*] Invalid khapp, magic: "+magic.decode("UTF-8"))
        exit()
    
    
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
    
    psm_dev = False

    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" # Header IV, used to find the real IV
    key = b"\x4E\x29\x8B\x40\xF5\x31\xF4\x69\xD2\x1F\x75\xB1\x33\xC3\x07\xBE" # Header key for PSM Runtime and used in all retail games.
    psm_dev_key = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF" # Header key for PSM Dev, used for all files encrypted with psm_encryptor.dll
    runtime_game_key = b"\xA8\x69\x3C\x4D\xF0\xAE\xED\xBC\x9A\xBF\xD8\x21\x36\x92\x91\x2D" # key for the PlayStation Mobile Runtime (eg used in Sce.PlayStation.Core.dll)

    total_blocks = math.floor(os.path.getsize(input_filename) / 0x8000)+1

    fd = open(input_filename, "rb")
    
    # Check magic is "PSSE" or "PSME"
    header = fd.read(4)
    if header != b"PSSE" and header != b"PSME":
        print("[*] "+input_filename.decode("UTF-8")+" is not a valid PSSE File")
        print("[*] Is it already decrypted?")
        exit()
    
    # Check PSSE Version is 0x1 (not sure what it would be otherwise)
    fd.seek(0x4, 0)
    version = struct.unpack('i', fd.read(4))[0]
    if version != 0x01:
        print("[*] Unsupported PSSE version: "+str(version))
        exit()
    
    fd.seek(0x8, 0)
    file_size = struct.unpack('Q', fd.read(8))[0]
    
    fd.seek(0x10, 0)
    psse_type = struct.unpack('i', fd.read(4))[0]
    if psse_type != 0x1:
        print("[*] Unknown PSSE Type: "+str(psse_type))
        exit()
    
    fd.seek(0x14, 0)
    read_content_id = fd.read(0x24)
    if read_content_id == b"IP9100-NPXS10074_00-0000000000000000": # Sce.PlayStation.Core.dll
        game_key = runtime_game_key
    elif read_content_id == (b"\x00"*0x24): # PSM developer assistant doenst include a Content ID
        psm_dev = True
    elif content_id != read_content_id:
        print("[*] Content ID Mismatch! Expected: "+content_id.decode("UTF-8")+" but got"+read_content_id.decode("UTF-8"))
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
    
    total_file_data = b""
    
    for i in range(0, total_blocks):
        file_block = GetBlock(fd, i)
        total_file_data += file_block

    fd.close()
    
    total_file_data = total_file_data[:file_size] # trim to file_size
    
    md5 = hashlib.md5()
    md5.update(total_file_data)
    got_md5 = md5.digest()
    
    if file_md5 != got_md5: # Verify decrypted file.
        print("[*] MD5 Mismatch, Expected: "+binascii.hexlify(file_md5).decode("UTF-8")+" got: "+binascii.hexlify(got_md5).decode("UTF-8"))
        print("[*] The game key is most likely wrong.")
        exit();
        
    return total_file_data
    

if len(sys.argv) <= 1:
    print("PSSE Decryptor by SilicaAndPina v3")
    print("(for retail games)     <PSM_GAME_FOLDER>")
    print("(for PSM Dev Packages) <PSM_GAME_FOLDER> <PSM_PUBLISHER_KEY> <PSM_HKAPP_OR_KRNG>")
    print("(for anything)         <PSM_GAME_FOLDER> <PSM_GAME_KEY>")
    print("")
    print("For retail games, you require the RO/License/FAKE.RIF file")
    print("And for PSM Dev Packages, you need there original publisher key and keyring.")
    exit()
    
file = sys.argv[1]
fpath = file.encode("UTF-8")

# Some dumb dirbustnig shit.
applications_folder = b"/RO/Application/"
license_file = os.path.normpath(fpath+b"/RO/License/FAKE.rif")
psse_list = os.path.normpath(fpath+applications_folder+b"psse.list")

if not os.path.exists(psse_list):
    applications_folder = b"/Application/"
    license_file = os.path.normpath(fpath+b"/License/FAKE.rif")
    psse_list = os.path.normpath(fpath+applications_folder+b"psse.list")
    
    if not os.path.exists(psse_list):
        applications_folder = b"/"
        license_file = os.path.normpath(fpath+b"/../License/FAKE.rif")
        psse_list = os.path.normpath(fpath+applications_folder+b"psse.list")    
    
        if not os.path.exists(psse_list):
            print("[*] Cannot find psse.list.")
            exit()


# Direct specify direct game key
if len(sys.argv) == 3:
    game_key = sys.argv[2]


# Read from publisher license
if game_key == b"":
    if len(sys.argv) == 4:
        pkcs12name = sys.argv[2]
        khappname = sys.argv[3]
        print("[*] Reading Publisher Key and App Key")
        
        if not os.path.exists(pkcs12name):
            print("[*] Publisher Key not found")
            exit()
            
        if not os.path.exists(khappname):
            print("[*] App key file not found.")
            exit()
            
        ReadPublisherKey(pkcs12name, khappname)


# Read from fake.rif
if game_key == b"":
    if os.path.exists(license_file):   
        ReadGameKey(license_file)

 # Is this a particular file rather than a games folder?
if os.path.isfile(fpath):
    print("Decrypting: "+file)
    data = DecryptFile(file)
    open(fpath, "wb").write(data)
    exit()

# If game key is still unknown after all of this, abandon all hope!
if game_key == b"":
    print("[*] Game key is unknown, i cant decrypt this ! :(")
    exit()
    
print("[*] psse.list: "+psse_list.decode("UTF-8")) 
print("[*] Using game key: "+binascii.hexlify(game_key).decode("UTF-8"))


file_data = DecryptFile(psse_list)
file_list = file_data.replace(b"\r", b"").split(b"\n")

for psse_file in file_list:
    if psse_file == b"":
        continue
    file_path = os.path.normpath(fpath+applications_folder+psse_file)
    print("[*] Decrypting: "+file_path.decode("UTF-8"))
    if os.path.exists(file_path):
        decrypted_data = DecryptFile(file_path)
        open(file_path, "wb").write(decrypted_data)
    else:
        print("[*] Error: File not Found: "+file_path.decode("UTF-8"))
    

open(psse_list, "wb").write(file_data)
print("[*] Decryption Complete!")
