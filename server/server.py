import socket
import rsa
import os

MAX_RECV = 2048
KEY_LEN = 96 # To-Do: exchange KEY_LEN
CLIENT_HELLO = 'Hello, server.'
SERVER_HELLO = 'Hello, client.'
CLIENT_DONE = 'Done, server.'
SERVER_DONE = 'Done, client.'

def kenc(data, key):
    enc = []
    key_len = len(key)
    for idx, ch in enumerate(data):
        enc.append(chr(ord(ch)^ord(key[idx%key_len])))
    return ''.join(enc)

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

    # normal communication
    while True:
        msg = sub_sock.recv(MAX_RECV)
        print str(client_addr)+':', msg # DEBUG
        sub_sock.send(msg)
        print 'Replied.'
        if msg.split(' ')[0] == 'cmd':
            if ''.join(msg.split(' ')[1:]) == 'quit':
                exit()
        elif msg.split(' ')[0] == 'quit':
            break;
    sub_sock.close()

sock.close()