#-*- coding:utf-8 -*-
import pefile
import os

pth = r'C:\Users\kira\Desktop\\'
pe_name = 'enclave_demo.dll'
pe_map = 'enclave_demo.map'
pe_xml = 'enclave_demo.config.xml'
key_file = 'enclave_demo_private.pem'
pe = pefile.PE(pth + pe_name)
with open(pth + pe_map, 'rb') as f:
    binmap = f.readlines()

enc_key = '*'
klen = len(enc_key)
with open('SGXWhiteList.txt') as f:
    func_list = [line.split('\n')[0] for line in f.readlines()]
func_list = ['_'+func for func in func_list] # SGX func_name start with _
offs_list = []

# close base-addr randomization
# change this byte will cause sgx_create_enclave return 1
# pe.OPTIONAL_HEADER.DllCharacteristics &= 0xff00

# set .text section writable
print 'Setting write permission.'
for section in pe.sections:
    if section.Name == ".text\x00\x00\x00":
        section.Characteristics |= 0x80000000 # #define IMAGE_SCN_MEM_WRITE 0x80000000 // Section is writeable.
        text_base = section.PointerToRawData
        break

# extract function address
print 'Extracting function address.'
for idx, line in enumerate(binmap): # To-Do: speed optimize
    line = line.split()
    if len(line) < 2:
        continue
    for func in func_list:
        if func == line[1]: # To-Do: exception - if line is the last function of current section...
            start = text_base + int(line[0].split(':')[1], 16)
            end = text_base + int(binmap[idx+1].split()[0].split(':')[1], 16)
            offs_list.append((start, end))

print 'Sanitizing...'
for func_id, offs in enumerate(offs_list):
    enc_bytes = []
    func_bytes = pe.get_memory_mapped_image()[offs[0]+0xa00:offs[1]+0xa00] # why 0xa00?
    # print ['%02x' % ord(i) for i in func_bytes[:10]]
    for idx, byte in enumerate(func_bytes):
        enc_byte = ord(byte)^ord(enc_key[idx%klen])
        enc_bytes.append(chr(enc_byte))
        pe.set_bytes_at_offset(offs[0]+idx, bytes(chr(0)))
    with open(func_list[func_id][1:]+'.secret', 'wb') as f:
        f.write(''.join(enc_bytes))

pe.write(filename='enc.dll')

# sign enc enclave 
# `sgx_sign sign -enclave enclave.dll -config config.xml -out enclave_signed.dll -key private.pem`
out_name = pe_name.replace('.', '.signed.')
os.system('sgx_sign sign -enclave enc.dll -config %s -out %s -key %s' % (pe_xml, out_name, key_file))
