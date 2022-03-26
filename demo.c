// clang -o demo demo.c
//

#include <stdlib.h>
#include <stdio.h>

int add(int a, int b) {
	return a + b;
}

int main(int  argc, char **argv) {
	for (;;) {
		printf("[demo] Enter two numbers: ");
		int a, b;
		scanf("%d %d", &a, &b);
		int res = add(a, b);
		printf("[demo] %d + %d = %d\n", a, b, res);
	}
	return 0;
}
