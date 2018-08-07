// app_hw3.cpp : console app entry
//

#include "stdafx.h"
#include "enclave_hw3_u.h"
#include "sgx_capable.h"
#include "sgx_uae_service.h"
#include "sgx_tcrypto.h"
#include "sgx_urts.h"
#define ENCLAVE_FILE _T("enclave_hw3.signed.dll")
sgx_enclave_id_t enclaveId = NULL;
sgx_launch_token_t token = { 0 };
int updated;

void unsafe_printf(char* str) {
	printf("from SGX: ");
	puts(str);
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

int getFileLen(FILE *fp) { // waiting for test
	fseek(fp, 0L, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	return size;
}

int main() {
	sgx_status_t ret = SGX_SUCCESS;
	if (!initializeEnclave()) {
		printf("init failed!\n");
		system("pause");
		return -1;
	}
	char des[20] = { 0 };
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

	give_me_pointer(enclaveId, key, strlen(key), rFuncList, offList, totalOff);

	hello_sgx(enclaveId, des);
	printf("%s\n", des);
	bye_sgx(enclaveId, des);
	printf("%s\n", des);
	if (!destroyEnclave()) {
		printf("failed to destory sgx\n");
		return -1;
	}
	system("pause");
	return 0;
}
