#include "enclave_hw3_t.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sgx_trts.h"

#define RET 0xc3
#define MAX_FUNC_COUNTS 100

void hello_sgx(char *des) {
	char str[] = "hello, SGX.\n";
	memcpy(des, str, strlen(str) + 1);
}

void bye_sgx(char *des) {
	char str[] = "bye, SGX.\n";
	memcpy(des, str, strlen(str) + 1);
}

void give_me_pointer(char* key, int keyLen, unsigned char* rFuncList, int* offList, int totalOff) {
	char *outBuffer = (char*)malloc(50); // DEBUG
	unsigned char *resBase = (unsigned char*)give_me_pointer;
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
		unsigned char *func = resBase; // To-Do: process var name func - resBase
		unsigned char *sFunc = funcList[funcID]; // To-Do: process var name sFunc - funcList[funcID]
		int overflow = 0;
		for (int i = 0; ; i++) {
			func[i] += (sFunc[i] ^ key[i%keyLen] + overflow);
			overflow = 0;
			if (func[i] < (sFunc[i] ^ key[i%keyLen])) { // overflow
				overflow = 0;
			}
			// unsafe_printf(outBuffer);
			if (func[i] == RET) { // To-Do: exception - if function have multiple RET
				break;
			}
		}
	}
}