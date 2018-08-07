#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JMP 0xe9
#define RET 0xc3
#define MAX_FUNC_NAME_LEN 100
#define MAX_FUNC_COUNTS 100

int testFunc(int a, int b);
int testFunc2(int c, int d);
int restore(char* key, int keyLen, unsigned char** funcList, int* offList);
int getFileLen(FILE *fp);
unsigned char* fixVSOff(unsigned char* funcBase);

int testFunc(int a, int b) {
	a += 666;
	b -= 123;
	a *= b;
	b += a;
	printf("your first flag is here: cnss{%08x-%08x-%08x-%08x}, congratz.", a + b, a*b, a - b, (a + b)*(a - b));
	return 0;
}

int testFunc2(int c, int d) {
	c *= 666;
	d /= 123;
	c *= d;
	d += c;
	printf("your second flag is here: cnss{%08x-%08x-%08x-%08x}, congratz.", c + d, c*d, c - d, (c + d)*(c - d));
	return 0;
}

int restore(char* key, int keyLen, unsigned char** funcList, int* offList) {
	unsigned char *resBase = fixVSOff((unsigned char*)restore);
	// resBase = fixVSOff(resBase);
	printf("testFunc: %08x, testFunc2: %08x, restore: %08x\n", \
		(unsigned int)fixVSOff((unsigned char*)testFunc), (unsigned int)fixVSOff((unsigned char*)testFunc2), (unsigned int)fixVSOff((unsigned char*)restore)); // DEBUG
	for (int funcID = MAX_FUNC_COUNTS - 1; funcID > 0; funcID--) {
		while (offList[funcID] == 0) {
			funcID--;
		}
		resBase -= offList[funcID];
		printf("id: %d, base: %08x\n", funcID, resBase); // DEBUG
		unsigned char *func = resBase; // To-Do: process var name func - resBase
		unsigned char *sFunc = funcList[funcID]; // To-Do: process var name sFunc - funcList[funcID]
		int overflow = 0;
		for (int i = 0; ; i++) {
			func[i] += (sFunc[i] ^ key[i%keyLen] + overflow);
			overflow = 0;
			if (func[i] < (sFunc[i] ^ key[i%keyLen])) { // overflow
				overflow = 1;
			}
			if (func[i] == RET) { // To-Do: exception - if function have multiple RET
				break;
			}
		}
	}

	return 0;
}

int getFileLen(FILE *fp) { // waiting for test
	fseek(fp, 0L, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	return size;
}

unsigned char* fixVSOff(unsigned char* funcBase) {
	int vsOffs = 0;
	if (funcBase[0] == JMP) {
		funcBase++;
		vsOffs = *(int*)funcBase;
	}
	else {
		printf("Error: VS jump table not found.\n");
		exit(0);
	}
	funcBase += (vsOffs + 4);
	return funcBase;
}

int main() {
	char key[] = "123456"; // To-Do: get key from remote server
	puts("Key accepted.");

	FILE *whiteList = fopen("whiteList.txt", "r");
	char funcName[MAX_FUNC_NAME_LEN] = { 0 };
	unsigned char* funcList[MAX_FUNC_COUNTS] = { 0 };
	int offList[MAX_FUNC_COUNTS] = { 0 };
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
	}

	puts("Restore Start...");
	restore(key, strlen(key), funcList, offList);
	puts("Restore completed.");

	puts("Test...");
	testFunc(-665, 124);
	testFunc2(1, 123);
	puts("Test success.");
	getchar();
	return 0;
}