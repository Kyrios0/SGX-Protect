#include "enclave_demo_t.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
//#include <WinSock2.h>
//#include <WS2tcpip.h>
#include "sgx_trts.h"

#define MAX_RECV 2048
#define KEY_LEN 16 // 96 To-Do: exchange KEY_LEN
#define CLIENT_HELLO "Hello, server."
#define SERVER_HELLO "Hello, client."
#define CLIENT_DONE "Done, server."
#define SERVER_DONE "Done, client."

#define RET 0xc3
#define MAX_FUNC_COUNTS 100


int kcmp(unsigned char* data, unsigned char* key, int len) {
	// ret 1: check pass, ret 0: check failed.
	//len--;
	// To-Do: cmp strlen.
	if (len < 0) {
		unsafe_puts("Error: invalid cmp.");
		return -1;
	}
	// char outBuffer[50];
	for (int i = 0; i < len; i++) {
		if (data[i] != key[i]) {
			return 0;
		}
	}
	return 1;
}

void swap_char(unsigned char &a, unsigned char &b) {
	/*a ^= b;
	b ^= a;
	a ^= b;*/
	unsigned char c=a;
	a=b;
	b=c;
}

unsigned char* getSBox(unsigned char *key) {
	unsigned char *sBox, *keyT;
	sBox = (unsigned char*)malloc(256 * sizeof(char));
	keyT = (unsigned char*)malloc(256 * sizeof(char));

	for (int i = 0; i < 256; i++) {
		sBox[i] = i; // init sBox
		keyT[i] = key[i % KEY_LEN]; // init key
	}
	int j = 0;
	for (int i = 0; i < 256; i++) { // generate sBox
		j = (j + sBox[i] + keyT[i]) % 256;
		swap_char(sBox[i], sBox[j]);
	}
		
	free(keyT);
	keyT = 0;

	return sBox;
}

int rc4(unsigned char *inputStream, unsigned char *outputStream, unsigned char *key, int streamSize) {
	unsigned char *sBox = getSBox(key);
	unsigned char *in = inputStream, *out = outputStream;
	int i = 0, j = 0;

	// char *outBuffer = (char*)malloc(50);

	while (in < inputStream + streamSize) {
		i = (i + 1) % 256;
		j = (j + sBox[i]) % 256;
		swap_char(sBox[i], sBox[j]);

		*out = (unsigned char)(*in ^ sBox[(sBox[i] + sBox[j]) % 256]);
		
		in++;
		out++;
	}
	free(sBox);
	sBox = 0;
	return 0;
}

void kenc(unsigned char* data, unsigned char* key, int len) {
	/* easy xor
	for (int i = 0; i < len; i++) {
		data[i] ^= key[i%KEY_LEN];
	} 
	*/
	rc4(data, data, key, len);
	return;
}

RSA* loadPubKey(char* pks) {
	BIO* bio = BIO_new_mem_buf((void*)pks, -1); // -1: assume string is null terminated
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // NO NL

	RSA* rsaPubKey = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL); // Load the RSA key from the BIO
	if (!rsaPubKey) {
		unsafe_puts("ERROR: Could not load PUBLIC KEY!");
	}

	BIO_free(bio);
	return rsaPubKey;
}

void signClient() {
	int *pubKeyLen = (int*)malloc(sizeof(int));
	*pubKeyLen += 4;
	unsafe_getPubKeyLen(pubKeyLen);
	char *rsaPubKeyStr = (char*)malloc(*pubKeyLen);
	unsafe_getPubKey(rsaPubKeyStr, *pubKeyLen);

	// initRSA
	RSA *rsa = loadPubKey(rsaPubKeyStr);

	unsafe_puts("Load key success.");

	char *servAddr = "127.0.0.1";
	int servPort = 10240;
	int *sock = (int*)malloc(sizeof(int));
	int *intRet = (int*)malloc(sizeof(int));
	unsafe_initSocket(intRet, sock, servAddr, servPort);
	unsafe_puts("Connected!");
	/*
	address = ('127.0.0.1', 10240)
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(address)
	print 'Connected!'
	*/

	unsigned char *msgBuff = (unsigned char*)malloc(MAX_RECV);
	unsigned char *encBuff = (unsigned char*)malloc(MAX_RECV);
	unsigned char *preKey = (unsigned char*)malloc(KEY_LEN);
	int cipherLen = 0;
	sgx_read_rand(preKey, KEY_LEN);
	memcpy(encBuff, CLIENT_HELLO, strlen(CLIENT_HELLO));
	memcpy(encBuff + strlen(CLIENT_HELLO), preKey, KEY_LEN);
	cipherLen = RSA_public_encrypt(strlen(CLIENT_HELLO) + KEY_LEN, encBuff, msgBuff, rsa, RSA_PKCS1_PADDING);
	unsafe_send(intRet, *sock, (char*)msgBuff, cipherLen, 0);
	/*
	# Shakehand Phase
	pre_key = os.urandom(KEY_LEN)
	s.send(rsa.encrypt(CLIENT_HELLO+pre_key, pub_key)) # hello; pre_key;
	*/
	
	memset(msgBuff, 0, MAX_RECV);
	unsafe_recv(intRet, *sock, (char*)msgBuff, MAX_RECV, 0);
	kenc(msgBuff, preKey, MAX_RECV);
	unsigned char *connKey = (unsigned char*)malloc(KEY_LEN);
	unsigned char *servChall = (unsigned char*)malloc(KEY_LEN);
	unsigned char *clieChall = (unsigned char*)malloc(KEY_LEN);
	
	memcpy(connKey, msgBuff, KEY_LEN);
	memcpy(servChall, msgBuff + KEY_LEN, KEY_LEN);
	sgx_read_rand(clieChall, KEY_LEN);
	kenc(servChall, connKey, KEY_LEN);
	memcpy(encBuff, servChall, KEY_LEN);
	memcpy(encBuff + KEY_LEN, clieChall, KEY_LEN);
	cipherLen = RSA_public_encrypt(2 * KEY_LEN, encBuff, msgBuff, rsa, RSA_PKCS1_PADDING);
	
	unsafe_send(intRet, *sock, (char*)msgBuff, cipherLen, 0);
	
	unsafe_puts("Challenge Sent.");
	
	/*
	data = kenc(s.recv(MAX_RECV), pre_key) # key; chall
	conn_key, server_chall = data[:KEY_LEN], data[KEY_LEN:]
	client_chall = os.urandom(KEY_LEN)
	s.send(rsa.encrypt(kenc(server_chall, conn_key)+client_chall, pub_key)) # response; chall
	print 'Challenge Sent.'
	*/

	unsafe_recv(intRet, *sock, (char*)msgBuff, MAX_RECV, 0);
	kenc(msgBuff, preKey, *intRet);
	unsigned char *resp = (unsigned char*)malloc(KEY_LEN);
	unsigned char *done = (unsigned char*)malloc(KEY_LEN);
	memcpy(resp, msgBuff, KEY_LEN);
	memcpy(done, msgBuff + KEY_LEN, strlen(SERVER_DONE));
	kenc(resp, connKey, KEY_LEN);
	unsafe_puts("[d] Check Response."); // comment this line may cause bug
	if (kcmp(resp, clieChall, KEY_LEN)) {
		unsafe_puts("Challenge Pass!");
	}
	else {
		unsafe_puts("Error: Shakehand Fail - Challenge Failed.");
		return; // EXIT
	}
	if (kcmp(done, (unsigned char*)SERVER_DONE, strlen(SERVER_DONE))) {
		unsafe_puts("Shakehand Success.");
	}
	else {
		unsafe_puts("Error: Shakehand Fail - Server Done Failed");
		return; // EXIT
	}
	/*
	data = s.recv(MAX_RECV)
	data = kenc(data, pre_key) # response; done;
	resp, done = data[:KEY_LEN], data[KEY_LEN:]
	if(kenc(resp, conn_key) == client_chall):
	print 'Challenge Pass!'
	else:
	print 'Error: Shakehand Fail - Challenge Failed'
	exit()
	if done == SERVER_DONE:
	print 'Shakehand Success.'
	else:
	# print "recvd:", done
	print 'Error: Shakehand Fail - Server Done Failed'
	exit()
	*/

	char *outBuff = (char*)malloc(50);
	unsigned char *cmdQuit = (unsigned char*)"quit";
	unsigned char *cmdCmdQuit = (unsigned char*)"cmd quit";
	kenc(cmdQuit, connKey, 4);
	kenc(cmdCmdQuit, connKey, 8);

	while (true) {
		unsafe_fgets(intRet, (char*)msgBuff);
		kenc(msgBuff, connKey, *intRet);
		unsafe_send(intRet, *sock, (char*)msgBuff, *intRet, 0);
		if (kcmp(msgBuff, cmdQuit, strlen("quit")) ||
			kcmp(msgBuff, cmdCmdQuit, strlen("cmd quit"))) {
			unsafe_puts("Quit recvd. Bye.");
			return;
		}
		unsafe_recv(intRet, *sock, (char*)msgBuff, MAX_RECV, 0);
		kenc(msgBuff, connKey, *intRet);
		unsafe_puts((char*)msgBuff);

	}
	/*
	while True:
	msg = raw_input()
	s.send(kenc(msg, conn_key))
	if (msg == 'quit') | (msg == 'cmd quit'):
	exit()
	data = kenc(s.recv(MAX_RECV), conn_key)
	print 'Server: ', data

	*/

}

void restore(char* key, int keyLen, unsigned char* rFuncList, int* offList, int totalOff) {
	char *outBuffer = (char*)malloc(50);
	for (int i = 0; i < MAX_FUNC_COUNTS; i++) {
		if (offList[i] != 0) {
			snprintf(outBuffer, 50, "offlist[%d]: 0x%x", i, offList[i]);
			unsafe_puts(outBuffer);
		}
	}
	unsigned char *resBase = (unsigned char*)restore;
	unsigned char* funcList[MAX_FUNC_COUNTS] = { 0 };

	for (int funcID = 0; funcID < MAX_FUNC_COUNTS && offList[funcID] > 0; funcID++) { // rebuild
		unsigned char *rFunc = (unsigned char*)malloc(offList[funcID]);
		memcpy(rFunc, rFuncList, offList[funcID]);
		rFuncList += offList[funcID];
		funcList[funcID] = rFunc;
	}
	for (int funcID = MAX_FUNC_COUNTS - 1; funcID >= 0; funcID--) {
		while (offList[funcID] == 0) {
			funcID--;
		}
		resBase -= offList[funcID];
		snprintf(outBuffer, 50, "id: %d, base: %08x", funcID, resBase);
		unsafe_puts(outBuffer);
		unsigned char *func = resBase; // To-Do: process var name [func - resBase]
		unsigned char *sFunc = funcList[funcID]; // To-Do: process var name [sFunc - funcList[funcID]]
		int overflow = 0;
		for (int i = 0; ; i++) {
			func[i] += (sFunc[i] ^ key[i%keyLen] + overflow);
			overflow = 0;
			if (func[i] < (sFunc[i] ^ key[i%keyLen])) { // overflow
				overflow = 0;
			}
			if (func[i] == RET) { // To-Do: exception - if function have multiple RET
				break;
			}
		}
	}
	snprintf(outBuffer, 50, "[d]: restore completed.");
	unsafe_puts(outBuffer);
}