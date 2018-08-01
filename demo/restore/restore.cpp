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

int restore(char* key, int len) {
	char *decKey = (char*)malloc(len);
	memcpy(decKey, key, len);
	unsigned char *func = (unsigned char*)testFunc;
	int vsOffs = 0;
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
		func[i] ^= decKey[i%len];
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
	restore(key, strlen(key));
	puts("Restore completed.");
	puts("Test...");
	testFunc(-665, 124);
	puts("Test success.");
	getchar();
	return 0;
}