#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/sha512.h"
#include "mbedtls/cipher.h"
#include "crypto.h"

int encrypt(char *arg1, char *arg2, char *arg3) {

	FILE *input, *output, *keyfile;
	unsigned char key[16];	
	unsigned char IV[16];

	input = fopen(arg1, "rb");

	if (!input)
	{
		printf("coudlnt open input file\n");
		return 1;
	}

	output = fopen(arg2, "wb");

	if (!output)
	{
		printf("coudlnt open output file\n");
		fclose(input);
		return 1;
	}

	keyfile = fopen(arg3, "rb");

	if (!keyfile)
	{
		printf("coudlnt open key file\n");
		fclose(input);
		fclose(output);
		return 1;
	}

	if (fread(key, 1, 16, keyfile) != 16)
	{
		printf("fread failed\n");
		fclose(input);
		fclose(output);
		fclose(keyfile);
		return 6;
	}

	if (fread(IV, 1, 16, keyfile) != 16)
	{
		printf("fread failed\n");
		fclose(input);
		fclose(output);
		fclose(keyfile);
		return 6;
	}

	fclose(keyfile);

	mbedtls_cipher_context_t aes_ctx;
	mbedtls_sha512_context sha_ctx;
	unsigned char cinput[16];
	unsigned char coutput[16];
	unsigned char sha_output[64];
	unsigned int n;

	mbedtls_cipher_setup(&aes_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC));
	mbedtls_cipher_set_padding_mode(&aes_ctx, MBEDTLS_PADDING_PKCS7);

	mbedtls_sha512_init(&sha_ctx);
	mbedtls_sha512_starts(&sha_ctx, 0);

	fseek(input, 0, SEEK_END);
	int filesize = ftell(input);
	rewind(input);

	mbedtls_cipher_set_iv(&aes_ctx, IV, 16);
	mbedtls_cipher_setkey(&aes_ctx, key, 128, MBEDTLS_ENCRYPT);

	for (int offset = 0; offset < filesize; offset += 16)
	{
		n = (filesize - offset > 16) ? 16 : (int)
			(filesize - offset);

		if (fread(cinput, 1, n, input) != (size_t)n)
		{
			printf("fread failed\n");
			fclose(input);
			fclose(output);
			return 3;
		}

		mbedtls_cipher_update(&aes_ctx, cinput, n, coutput, (size_t*)&n);
		mbedtls_sha512_update(&sha_ctx, coutput, n);

		if (fwrite(coutput, 1, n, output) != n)
		{
			printf("fwrite failed\n");
			fclose(input);
			fclose(output);
			return 4;
		}
	}

	mbedtls_cipher_finish(&aes_ctx, coutput, (size_t*)&n);
	mbedtls_sha512_update(&sha_ctx, coutput, n);
	mbedtls_sha512_finish(&sha_ctx, sha_output);

	if (fwrite(coutput, 1, n, output) != n)
	{
		printf("fwrite failed\n");
		fclose(input);
		fclose(output);
		return 4;
	}

	if (fwrite(sha_output, 1, 64, output) != 64)
	{
		printf("fwrite failed\n");
		fclose(input);
		fclose(output);
		return 4;
	}

	fclose(input);
	fclose(output);

	return 0;
}

int decrypt(char *arg1, char *arg2, char *arg3) {
	FILE *input, *output, *keyfile;
	unsigned char key[16];
	unsigned char IV[16];

	input = fopen(arg1, "rb");

	if (!input)
	{
		printf("coudlnt open input file\n");
		return 1;
	}

	output = fopen(arg2, "wb");

	if (!output)
	{
		printf("coudlnt open output file\n");
		fclose(input);
		return 1;
	}

	keyfile = fopen(arg3, "rb");

	if (!keyfile)
	{
		printf("coudlnt open key file\n");
		fclose(input);
		fclose(output);
		return 1;
	}

	if (fread(key, 1, 16, keyfile) != 16)
	{
		printf("fread failed\n");
		fclose(input);
		fclose(output);
		fclose(keyfile);
		return 6;
	}

	if (fread(IV, 1, 16, keyfile) != 16)
	{
		printf("fread failed\n");
		fclose(input);
		fclose(output);
		fclose(keyfile);
		return 6;
	}

	fclose(keyfile);

	mbedtls_cipher_context_t aes_ctx;
	mbedtls_sha512_context sha_ctx;
	unsigned char cinput[16];
	unsigned char coutput[16];
	unsigned char sha_output[64];
	unsigned int n;

	mbedtls_cipher_setup(&aes_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC));
	mbedtls_cipher_set_padding_mode(&aes_ctx, MBEDTLS_PADDING_PKCS7);

	mbedtls_sha512_init(&sha_ctx);
	mbedtls_sha512_starts(&sha_ctx, 0);

	fseek(input, 0, SEEK_END);
	int filesize = ftell(input);
	rewind(input);

	mbedtls_cipher_setkey(&aes_ctx, key, 128, MBEDTLS_DECRYPT);
	mbedtls_cipher_set_iv(&aes_ctx, IV, 16);

	if (filesize < 64)
	{
		printf("file is invalid\n");
		fclose(input);
		fclose(output);
		return 2;
	}

	filesize -= 64;

	for (int offset = 0; offset < filesize; offset += 16)
	{
		n = (filesize - offset > 16) ? 16 : (int)
			(filesize - offset);

		if (fread(cinput, 1, n, input) != n)
		{
			printf("fread failed\n");
			fclose(input);
			fclose(output);
			return 3;
		}
		
		mbedtls_sha512_update(&sha_ctx, cinput, n);
		mbedtls_cipher_update(&aes_ctx, cinput, n, coutput, (size_t*)&n);

		if (fwrite(coutput, 1, n, output) != n)
		{
			printf("fwrite failed\n");
			fclose(input);
			fclose(output);
			return 4;
		}
	}

	mbedtls_cipher_finish(&aes_ctx, coutput, (size_t*)&n);

	if (fwrite(coutput, 1, n, output) != n)
	{
		printf("fwrite failed\n");
		fclose(input);
		fclose(output);
		return 4;
	}

	unsigned char control_hash[64];
	fread(control_hash, 1, 64, input);

	mbedtls_sha512_finish(&sha_ctx, sha_output);

	if (memcmp(control_hash, sha_output, 64) != 0)
	{
		printf("wrong hash\n");
		fclose(input);
		fclose(output);
		return 5;
	}
	else
	{
		printf("hash ok\n");
	}

	fclose(input);
	fclose(output);

	return 0;
}