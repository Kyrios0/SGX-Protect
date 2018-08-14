#pragma once
#include <WinSock2.h>
#pragma comment(lib,"WS2_32.lib")

FILE *pubFile = fopen("C:\\Users\\pzhxb\\Desktop\\kyrios_SGX\\Github\\SGX-Protect\\server\\tls_public_key_2048.pem", "rb");
FILE *privFile = fopen("C:\\Users\\pzhxb\\Desktop\\kyrios_SGX\\Github\\SGX-Protect\\server\\tls_private_key_2048.pem", "rb"); // test

int unsafe_initSocket(int * s, char * ip, int port) {
	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA data;
	if (WSAStartup(sockVersion, &data) != 0) {
		return -1;
	}
	unsigned int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		return -1;
	}

	sockaddr_in serAddr;
	serAddr.sin_family = AF_INET;
	//inet_pton(AF_INET, ip, &serAddr.sin_addr);
	serAddr.sin_addr.S_un.S_addr = inet_addr(ip);

	serAddr.sin_port = htons(port);
	if (connect(sock, (sockaddr*)&serAddr, sizeof(sockaddr_in)) == SOCKET_ERROR) {
		closesocket(sock);
		return -1;
	}

	*s = sock;
	return 0;
}

int unsafe_send(int s, char * buf, int len, int flags) {
	int returnValue = send(s, buf, len, flags);

	return returnValue;
}

int unsafe_recv(int s, char * buf, int len, int flags) {
	int returnValue = recv(s, buf, len, flags);

	return returnValue;
}

int unsafe_closeSocket(int s) {
	return closesocket(s);
}

void unsafe_getPubKeyLen(int* ret) {
	fseek(pubFile, 0L, SEEK_END);
	int size = ftell(pubFile);
	fseek(pubFile, 0L, SEEK_SET);
	*ret = size;
	return;
}
void unsafe_getPrivKeyLen(int* ret) {
	fseek(privFile, 0L, SEEK_END);
	int size = ftell(privFile);
	fseek(privFile, 0L, SEEK_SET);
	*ret = size;
	return;;
}
void unsafe_getPubKey(char* rsaPubKey, int keyLen) {
	fread(rsaPubKey, 1, keyLen, pubFile);
	*(int*)(rsaPubKey + keyLen) = 0; // To-Do: fix \x00 panic
	return;
}
void unsafe_getPrivKey(char* rsaPrivKey, int keyLen) {
	fread(rsaPrivKey, 1, keyLen, privFile);
	*(int*)(rsaPrivKey + keyLen) = 0; // To-Do: fix \x00 panic
	return;
}

void unsafe_puts(char* str) {
	printf("from SGX: ");
	puts(str);
	return;
}

void unsafe_printL(unsigned char* str, int len) {
	for (int i = 0; i < len; i++) {
		printf("%02x ", str[i]);
	}
	puts("");
	return;
}

int unsafe_fgets(char *str) {
	printf("SGX_fgets:");
	fgets(str, 50, stdin);
	int len = strlen(str) - 1;
	str[len] = 0;
	return len;
}
