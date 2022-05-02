# psse-decrypt
Decrypt PSSE layer of PSM Games (on PC)
Works on Unity and PSM games, and meets all requirements of: https://github.com/vita-nuova/bounties/issues/73
Usage: ``psse_decrypt.py <psm game folder>``

Discoveries: 
 - Every game has its own aes-128-cbc key, (located 0x120 bytes into FAKE.rif), so its probably not possible to decrypt a game without a license
 - PSM Runtime has a hard coded key for its runtime libaries. - A8693C4DF0AEEDBC9ABFD8213692912D 

After 9 years, the encryption used by PlayStation Mobile games is finally cracked!!

Requires:
  pycryptodome
  cryptography
