#include "mbedtls/cipher.h"
#include "mbedtls/aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/md.h"
#include "mbedtls/aesni.h"
#include "mbedtls/sha512.h"

using namespace std;

//"C:\Users\Marek Vanèík\Documents\Visual Studio 2015\Projects\mbedtls-2.2.1\visualc\VS2010\Release\mbedTSL.lib"

int main(int argc, char *argv[]) {

	FILE *input, *output, *keyfile;
	int offset;
	//unsigned char buffer[1024];
	unsigned char key[7];
	unsigned char IV[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	unsigned char cinput[16];
	unsigned char coutput[16];

	size_t input_len = 40;
	size_t output_len = 0;

	//mbedtls_aes_context aes_ctx;
	mbedtls_cipher_context_t aes_ctx;
	mbedtls_sha512_context sha_ctx;

	input = fopen(argv[1], "rb");

	if (!input)
	{
		printf("coudlnt open input file\n");
		return 0;
	}

	output = fopen(argv[2], "wb");

	if (!output)
	{
		printf("coudlnt open output file\n");
		return 0;
	}

	keyfile = fopen(argv[3], "rb");

	if (!keyfile)
	{
		printf("coudlnt open key file\n");
		return 0;
	}

	//mbedtls_aes_init(&aes_ctx);

	fread(key, 1, 7, keyfile);

	mbedtls_cipher_setup(&aes_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC));
	mbedtls_cipher_set_padding_mode(&aes_ctx, MBEDTLS_PADDING_PKCS7);

	int filesize = fseek(input, 0, SEEK_END);

	if (strcmp(argv[4], "-e") == 0)  // encryption
	{
		mbedtls_cipher_set_iv(&aes_ctx, IV, 16);
		mbedtls_cipher_setkey(&aes_ctx, key, 128, MBEDTLS_ENCRYPT);

		fwrite(IV, 1, 16, output);

		for (offset = 0; offset < filesize; offset += 16)
		{
			int n = (filesize - offset > 16) ? 16 : (int)
				(filesize - offset);

			if (fread(cinput, 1, n, input) != (size_t)n)
			{
				printf("fread failed\n");
				return 0;
			}

			mbedtls_cipher_update(&aes_ctx, cinput, n, coutput, (size_t*)&n);

			//mbedtls_aes_setkey_enc(&aes_ctx, key, 128);
			//mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, n, IV, cinput, coutput);

			if (fwrite(coutput, 1, n, output) != n)
			{
				printf("fwrite failed\n");
				return 0;
			}
		
			//memcpy(IV, cinput, 16);
		}

		// HASH

		rewind(output);
		mbedtls_sha512_init(&sha_ctx);
		mbedtls_sha512_starts(&sha_ctx, 0);

		for (offset = 0; offset < filesize; offset += 16)
		{
			int n = (filesize - offset > 16) ? 16 : (int)
				(filesize - offset);

			if (fread(cinput, 1, n, input) != (size_t)n)
			{
				printf("fread failed\n");
				return 0;
			}

			mbedtls_sha512_update(&sha_ctx, cinput, n);
		}

		unsigned char sha_output[64];
		mbedtls_sha512_finish(&sha_ctx, sha_output);
		fwrite(sha_output, 1, 64, output);
	}

	else if (strcmp(argv[4], "-d") == 0)  // decrytion
	{
		// CONTROL HASH

		unsigned char control_hash[65];

		fseek(input, 64, SEEK_END);
		fread(control_hash, 1, 64, input);

		mbedtls_sha512_init(&sha_ctx);
		mbedtls_sha512_starts(&sha_ctx, 0);

		for (offset = 0; offset < filesize - 64; offset += 16)
		{
			int n = ((filesize - 64) - offset > 16) ? 16 : (int)
				((filesize - 64) - offset);

			if (fread(cinput, 1, n, input) != (size_t)n)
			{
				printf("fread failed\n");
				return 0;
			}

			mbedtls_sha512_update(&sha_ctx, cinput, n);
		}

		unsigned char sha_output[64];
		mbedtls_sha512_finish(&sha_ctx, sha_output);
		
		if (memcmp(control_hash, sha_output, 64) != 0)
		{
			printf("wrong hash\n");
			return 0;
		}
		else
		{
			printf("hash ok\n");
		}

		rewind(input);

		// DECRYPT

		fread(IV, 1, 16, input);

		mbedtls_cipher_set_iv(&aes_ctx, IV, 16);
		mbedtls_cipher_setkey(&aes_ctx, key, 128, MBEDTLS_DECRYPT);

		for (offset = 0; offset < filesize - 9; offset += 16)
		{
			int n = ((filesize - 64) - offset > 16) ? 16 : (int)
				((filesize - 64) - offset);

			if (fread(cinput, 1, n, input) != (size_t)n)
			{
				printf("fread failed\n");
				return 0;
			}

			mbedtls_cipher_update(&aes_ctx, cinput, n, coutput, (size_t*)&n);

			//mbedtls_aes_setkey_enc(&aes_ctx, key, 128);
			//mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, n, IV, cinput, coutput);

			if (fwrite(coutput, 1, n, output) != n)
			{
				printf("fwrite failed\n");
				return 0;
			}

			//memcpy(IV, cinput, 16);
		}
	}

	else
	{
		printf("unknown operation");
		return 0;
	}


}