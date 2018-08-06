#include "enclave_hw3_t.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sgx_trts.h"

#define RET 0xc3

void hello_sgx(char *des);
void give_me_pointer(char *des);

void hello_sgx(char *des) {
	char str[] = "hello, SGX.";
	memcpy(des, str, strlen(str) + 1);
}

void give_me_pointer(unsigned char *sFunc, int funcLen) {
	char decKey[] = "123456"; // To-Do: get key from remote server
	int keyLen = strlen(decKey), overflow = 0;
	unsigned char *func = (unsigned char*)hello_sgx;
	char *outBuffer = (char*)malloc(20);

	for (int i = 0; ; i++) {
		// snprintf(outBuffer, 20, "%02x: %02x", func[i], ((sFunc[i] ^ decKey[i%keyLen]) + overflow));
		func[i] += ((sFunc[i] ^ decKey[i%keyLen]) + overflow);
		overflow = 0;
		if (func[i] < (sFunc[i] ^ decKey[i%keyLen])) { // overflow
			overflow = 0; // DEBUG
		}
		// snprintf(outBuffer + 6, 20, " %02x: %02x", i, func[i]);
		// unsafe_printf(outBuffer);
		if (func[i] == RET) { // To-Do: exception - if function have multiple RET
			break;
		}
	}
}