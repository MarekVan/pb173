//#define _CRT_NONSTDC_NO_WARNINGS
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// NIST

int main(int argc, char *argv[]) {

	if (argc < 5)
	{
		printf("invalid number of arguments\n");
		return 0;
	}

	if (strcmp(argv[4], "-e") == 0)  // encryption
	{
		return encrypt(argv[1], argv[2], argv[3]);
	}

	else if (strcmp(argv[4], "-d") == 0)  // decrytion
	{
		return decrypt(argv[2], argv[1], argv[3]);
	}

	else
	{
		printf("unknown operation\n");
	}

	return 0;
}