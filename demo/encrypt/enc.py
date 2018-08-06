import pefile

pth = r"C:\Users\pzhxb\Desktop\kyrios_SGX\Github\SGX-Protect\demo\exetest\\"
pe_name = 'restore.exe'
pe_map = 'restore.map'
pe = pefile.PE(pth + pe_name)
with open(pth + pe_map, 'rb') as f:
    binmap = f.readlines()

enc_key = '123456'
klen = len(enc_key)
func_list = ['testFunc']
offs_list = []

# close base-addr randomization
# test anti-randomization mode
# pe.OPTIONAL_HEADER.DllCharacteristics &= 0xff00

# set .text section writable
for section in pe.sections:
    if section.Name == ".text\x00\x00\x00":
        section.Characteristics |= 0x80000000 # #define IMAGE_SCN_MEM_WRITE 0x80000000 // Section is writeable.
        text_base = section.PointerToRawData
        break

# extract function address
for idx, line in enumerate(binmap): # To-Do: speed optimize
    line = line.split()
    if len(line) < 2:
        continue
    for func in func_list:
        if func in line[1]: # To-Do: exception - if line is the last function of current section...
            start = text_base + int(line[0].split(':')[1], 16)
            end = text_base + int(binmap[idx+1].split()[0].split(':')[1], 16)
            offs_list.append((start, end))

enc_bytes = [] # DEBUG
for offs in offs_list: # To-Do: process functions
    func_bytes = pe.get_memory_mapped_image()[offs[0]:offs[1]]
    for idx, byte in enumerate(func_bytes):
        enc_byte = ord(byte)^ord(enc_key[idx%klen])
        enc_bytes.append(chr(enc_byte)) # DEBUG
        pe.set_bytes_at_offset(offs[0]+idx, bytes(chr(0)))

with open('testfunc1.secret', 'wb') as f: # DEBUG
    f.write(''.join(enc_bytes))         # DEBUG

pe.write(filename='enc.exe')
