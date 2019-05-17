// client_demo.cpp : console app entry
//

#include "stdafx.h"
#include <WS2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "enclave_demo_u.h"
#include "sgx_capable.h"
#include "sgx_uae_service.h"
#include "sgx_tcrypto.h"
#include "sgx_urts.h"
#include "unsafe.hpp"
#include "perf_test.h"

#pragma comment(lib,"WS2_32.lib")

#define ENCLAVE_FILE _T("enclave_demo.signed.dll")
#define MAX_FUNC_NAME_LEN 100
#define MAX_FUNC_COUNTS 100
#define KEY_LEN 16
sgx_enclave_id_t enclaveId = NULL;
sgx_launch_token_t token = { 0 };
int updated;

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

int pTest(int n) {
	for (int i = 0; i < n; i++) {
		if(aes_perf_test()) { 
			puts("Normal Test Failed.");
			return 1;
		}
	}
	return 0;
}

int main()
{
	sgx_status_t ret = SGX_SUCCESS;
	if (!initializeEnclave()) {
		printf("init failed!\n");
		system("pause");
		return -1;
	}

	// To-Do: attestion

	unsigned char key[KEY_LEN]; // To-Do: TLS - RSA module

	FILE *whiteList = fopen("SGXWhiteList.txt", "r");
	char funcName[MAX_FUNC_NAME_LEN] = { 0 };
	unsigned char* funcList[MAX_FUNC_COUNTS] = { 0 };
	int offList[MAX_FUNC_COUNTS] = { 0 };

	int totalOff = getTotalOff(whiteList, funcName, funcList, offList);
	unsigned char *rFuncList = getRFuncList(funcList, offList, totalOff);
	getKey(enclaveId, key); // keyLen = 16
	printf("%16s\n", key);
	restore(enclaveId, (char*)key, KEY_LEN, rFuncList, offList, totalOff);
	// signClient(enclaveId);
	int testCount = 10000; // aes: 10000, zuc: 50000, sm4: 200000
	int totalRound = 10;
	clock_t start, finish;
	double  duration, d1 = 0, d2 = 0, d3 = 0;
	// printf("AES-%d Test Start.\n", test_count);
	printf("%d-round AES-%d Test Start.\n", totalRound, testCount);
	for (int round = 0; round < totalRound; round++) {
		printf("----------------Round %d----------------\n", round);
		start = clock();
		pTest(testCount);
		finish = clock();
		duration = (double)(finish - start) / CLOCKS_PER_SEC;
		printf("Normal Test Completed.\n");
		printf("result: %.3lf seconds.\n", duration);
		d1 += duration;

		start = clock();
		perfTest(enclaveId, testCount);
		finish = clock();
		duration = (double)(finish - start) / CLOCKS_PER_SEC;
		printf("result: %.3lf seconds.\n", duration);
		d2 += duration;

		start = clock();
		perfXTest(enclaveId, testCount);
		finish = clock();
		duration = (double)(finish - start) / CLOCKS_PER_SEC;
		printf("result: %.3lf seconds.\n", duration);
		d3 += duration;
	}
	printf("Avg Time:\n Normal: %.4lf sec.\n Perf: %.4lf sec.\n PerfX: %.4lf sec.\n", d1 / (double)totalRound, d2 / (double)totalRound, d3 / (double)totalRound);
	
	if (!destroyEnclave()) {
		printf("failed to destory sgx\n");
		return -1;
	}
	system("pause");
	return 0;
}

