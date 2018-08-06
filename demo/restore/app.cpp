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
int main() {
	sgx_status_t ret = SGX_SUCCESS;
	if (!initializeEnclave()) {
		printf("init failed!\n");
		system("pause");
		return -1;
	}
	char des[20] = { 0 };
	unsigned char func[0x60] = { 0 };
	int funcLen = 0x60;
	FILE *f = fopen("func1.secret", "rb"); // To-Do: process functions
	for (int i = 0; i < funcLen; i++) {
		func[i] = fgetc(f);
	}
	give_me_pointer(enclaveId, func, funcLen);
	hello_sgx(enclaveId, des);
	printf("%s\n", des);
	if (!destroyEnclave()) {
		printf("failed to destory sgx\n");
		return -1;
	}
	system("pause");
	return 0;
}