import socket
import rsa
import os

MAX_RECV = 2048 # 2048
KEY_LEN = 16 # 96 To-Do: exchange KEY_LEN
CLIENT_HELLO = 'Hello, server.'
SERVER_HELLO = 'Hello, client.'
CLIENT_DONE = 'Done, server.'
SERVER_DONE = 'Done, client.'
SGX_key = '*'

def rc4(data, key):
    """RC4 encryption and decryption method."""
    S, j, out = list(range(256)), 0, []
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for ch in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(ch) ^ S[(S[i] + S[j]) % 256]))
    return "".join(out)

def kenc(data, key):
    """ easy xor
    enc = []
    key_len = len(key)
    for idx, ch in enumerate(data):
        enc.append(chr(ord(ch)^ord(key[idx%key_len])))
    return ''.join(enc)
    """
    return rc4(data, key)

with open('tls_private_key_2048.pem', 'rb') as privatefile:
    priv_key_data = privatefile.read()
priv_key = rsa.PrivateKey.load_pkcs1(priv_key_data, 'PEM')

with open('tls_public_key_2048.pem', 'rb') as publicfile:
    pub_key_data = publicfile.read()
pub_key = rsa.PublicKey.load_pkcs1(pub_key_data)

print 'Load Key Success.'

address = ('127.0.0.1', 10240)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(address)
sock.listen(5)

while True:
    sub_sock, client_addr = sock.accept()
    print 'Connected from', client_addr

    # Shakehand Phase
    # To-Do: exchange pub_key
    msg = rsa.decrypt(sub_sock.recv(MAX_RECV), priv_key) # hello; pre_key;
    hello, pre_key = msg[:len(CLIENT_HELLO)], msg[len(CLIENT_HELLO):]
    if(hello != CLIENT_HELLO):
        print 'Error: Shakehand Fail - Wrong Server Hello'
        exit()
    else:
        conn_key = os.urandom(KEY_LEN)
    server_chall = os.urandom(KEY_LEN)
    sub_sock.send(kenc(conn_key+server_chall, pre_key)) # key; chall # To-Do: sign
    print 'Challenge Sent.'
    msg = rsa.decrypt(sub_sock.recv(MAX_RECV), priv_key) # response; chall;
    resp, client_chall = msg[:KEY_LEN], msg[KEY_LEN:]
    if(kenc(resp, conn_key) == server_chall):
        print 'Challenge Pass!'
        sub_sock.send(kenc(kenc(client_chall, conn_key)+SERVER_DONE, pre_key)) # response; done; / To-Do: add hash
    else:
        print 'Error: Shakehand Fail - Challenge Failed'
        exit()
    print 'Shakehand Success.'

    # deliver key
    sub_sock.send(kenc(SGX_key, conn_key))
    print 'key delivered:', SGX_key
    sub_sock.close()
    exit()

sock.close()