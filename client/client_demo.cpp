// client_demo.cpp : console app entry
//

#include "stdafx.h"
// #include <windows.h>
// #include "unsafe.h"
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdio.h>
#include <string.h>
#include "enclave_demo_u.h"
#include "sgx_capable.h"
#include "sgx_uae_service.h"
#include "sgx_tcrypto.h"
#include "sgx_urts.h"
#pragma comment(lib,"WS2_32.lib")

#define ENCLAVE_FILE _T("enclave_demo.signed.dll")
sgx_enclave_id_t enclaveId = NULL;
sgx_launch_token_t token = { 0 };
int updated;

FILE *pubFile = fopen("C:\\Users\\pzhxb\\Desktop\\kyrios_SGX\\Github\\SGX-Protect\\server\\tls_public_key_2048.pem", "r");
FILE *privFile = fopen("C:\\Users\\pzhxb\\Desktop\\kyrios_SGX\\Github\\SGX-Protect\\server\\tls_private_key_2048.pem", "r");

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

bool initializeEnclave() {
	int stat = 0;
	try {
		stat = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &enclaveId, NULL); // To-Do: save token state.
	}
	catch (const char* msg) {
		printf("%s\n", msg);
	}

	printf("%d\n", GetLastError());
	if (stat != SGX_SUCCESS) {
		printf("Error: %d\n", stat);
		return false;
	}
	return true;
}
bool destroyEnclave() {
	if (sgx_destroy_enclave(enclaveId) != SGX_SUCCESS)
		return false;
	return true;
}

int main()
{
	sgx_status_t ret = SGX_SUCCESS;
	if (!initializeEnclave()) {
		printf("init failed!\n");
		system("pause");
		return -1;
	}
	/*char des[20] = { 0 };
	char key[] = "123456"; // To-Do: TLS - RSA module

	FILE *whiteList = fopen("SGXWhiteList.txt", "r");
	char funcName[MAX_FUNC_NAME_LEN] = { 0 };
	unsigned char* funcList[MAX_FUNC_COUNTS] = { 0 };
	int offList[MAX_FUNC_COUNTS] = { 0 };
	int totalOff = 0;
	for (int funcID = 0; fgets(funcName, 100, whiteList) != NULL; funcID++) {
		char *ent = 0;
		if ((ent = strstr(funcName, "\n")) != NULL) { // funcName.replace('\n', '\0')
			*ent = 0;
		}
		strcat(funcName, ".secret");
		printf("read file: %s\n", funcName); // LOG
		FILE *funcSecretFile = fopen(funcName, "r");
		int funcLen = getFileLen(funcSecretFile);
		unsigned char *funcSecret = (unsigned char*)malloc(funcLen);
		fread(funcSecret, 1, funcLen, funcSecretFile);
		funcList[funcID] = funcSecret;
		offList[funcID] = funcLen;
		totalOff += funcLen;
	}
	unsigned char *rFuncList = (unsigned char*)malloc(totalOff);
	unsigned char *rp = rFuncList;
	for (int funcID = 0; funcID < MAX_FUNC_COUNTS && offList[funcID] > 0; funcID++) {
		memcpy(rp, funcList[funcID], offList[funcID]);
		rp += offList[funcID];
	}

	restore(enclaveId, key, strlen(key), rFuncList, offList, totalOff);
	*/
	signClient(enclaveId);
	if (!destroyEnclave()) {
		printf("failed to destory sgx\n");
		return -1;
	}
	system("pause");
	return 0;
}