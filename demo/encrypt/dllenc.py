#-*- coding:utf-8 -*-
import pefile
import os

pth = r'C:\Users\pzhxb\Desktop\kyrios_SGX\vs\enclave_hw2\Debug\\'
pe_name = 'enclave_hw2.dll'
pe_map = 'enclave_hw2.map'
pe_xml = 'enclave_hw2.config.xml'
key_file = 'enclave_hw2_private.pem'
pe = pefile.PE(pth + pe_name)
with open(pth + pe_map, 'rb') as f:
    binmap = f.readlines()

enc_key = '123456'
klen = len(enc_key)
func_list = ['_hello_sgx'] # To-Do: process _func_name
offs_list = []

# close base-addr randomization
# change this byte will cause sgx_create_enclave return 1
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

for offs in offs_list:
    func_bytes = pe.get_memory_mapped_image()[offs[0]:offs[1]]
    for idx, byte in enumerate(func_bytes):
        enc_byte = ord(byte)^ord(enc_key[idx%klen])
        pe.set_bytes_at_offset(offs[0]+idx, bytes(chr(enc_byte)))

pe.write(filename='enc.dll')

# sign enc enclave 
# `sgx_sign sign -enclave enclave.dll -config config.xml -out enclave_signed.dll -key private.pem`
out_name = pe_name.replace('.', '.signed.')
os.system('sgx_sign sign -enclave enc.dll -config %s -out %s -key %s' % (pe_xml, out_name, key_file))
