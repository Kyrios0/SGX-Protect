#pragma once
#define ENCLAVE_FILE _T("enclave_demo.signed.dll")
#define MAX_FUNC_NAME_LEN 100
#define MAX_FUNC_COUNTS 100
#define KEY_LEN 16

extern sgx_enclave_id_t enclaveId;

int getFileLen(FILE *fp) {
	fseek(fp, 0L, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	return size;
}

int getTotalOff(FILE *whiteList, char* funcName, unsigned char** funcList, int* offList) {
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
	return totalOff;
}

unsigned char* getRFuncList(unsigned char** funcList, int* offList, int totalOff) {
	unsigned char* rFuncList = (unsigned char*)malloc(totalOff);
	unsigned char *rp = rFuncList;
	for (int funcID = 0; funcID < MAX_FUNC_COUNTS && offList[funcID] > 0; funcID++) {
		memcpy(rp, funcList[funcID], offList[funcID]);
		rp += offList[funcID];
	}
	return rFuncList;
}

int user_restore(char* whiteListName) {
	FILE *whiteList = fopen(whiteListName, "r");
	char funcName[MAX_FUNC_NAME_LEN] = { 0 };
	unsigned char* funcList[MAX_FUNC_COUNTS] = { 0 };
	int offList[MAX_FUNC_COUNTS] = { 0 };

	int totalOff = getTotalOff(whiteList, funcName, funcList, offList);
	unsigned char *rFuncList = getRFuncList(funcList, offList, totalOff);

	restore(enclaveId, rFuncList, offList, totalOff);
	return 0;
}