#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JMP 0xe9
#define RET 0xc3

int testFunc(int a, int b) {
	a += 666;
	b -= 123;
	a *= b;
	b += a;
	printf("your flag is here: cnss{%08x-%08x-%08x-%08x}, congratz.", a + b, a*b, a - b, (a + b)*(a - b));
	return 0;
}

int restore(char* key, int keyLen, unsigned char* oFunc, int funcLen) {
	char *decKey = (char*)malloc(keyLen);
	unsigned char *sFunc = (unsigned char*)malloc(funcLen);
	memcpy(decKey, key, keyLen);
	memcpy(sFunc, oFunc, funcLen);
	unsigned char *func = (unsigned char*)testFunc;
	int vsOffs = 0;
	int overflow = 0;
	short decByte = 0;
	if (func[0] == JMP) {
		func++;
		vsOffs = *(int*)func;
	}
	else {
		printf("Error: VS jump table not found.\n");
		exit(0);
	}
	func += (vsOffs + 4);
	for (int i = 0; ; i++) {
		func[i] += (sFunc[i] ^ decKey[i%keyLen] + overflow);
		overflow = 0;
		if (func[i] < (sFunc[i] ^ decKey[i%keyLen])) { // overflow
			overflow = 1;
		}
		if (func[i] == RET) { // To-Do: exception - if function have multiple RET
			break;
		}
	}
	return 0;
}

int main() {
	char key[] = "123456"; // To-Do: get key from remote server
	puts("Key accepted.");
	puts("Restore Start...");
	unsigned char func[0xc0] = { 0 };
	int funcLen = 0xc0;
	FILE *f = fopen("testfunc1.secret", "rb"); // To-Do: process functions
	for (int i = 0; i < funcLen; i++) {
		func[i] = fgetc(f);
	}
	restore(key, strlen(key), func, funcLen);
	puts("Restore completed.");
	puts("Test...");
	testFunc(-665, 124);
	puts("Test success.");
	getchar();
	return 0;
}