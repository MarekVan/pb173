#include "mbedtls/cipher.h"
#include "mbedtls/aes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/md.h"

using namespace std;

int main(int argc, char *argv[]) {

	FILE *input, *output, *keyfile;
	unsigned char key[8];
	unsigned char IV[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

	mbedtls_aes_context aes_ctx;
	mbedtls_md_context_t sha_ctx;

	input = fopen(argv[1], "rb");

	if (!input)
	{
		printf("coudlnt open input file");
		return 0;
	}

	output = fopen(argv[2], "wb");

	if (!output)
	{
		printf("coudlnt open output file");
		return 0;
	}

	keyfile = fopen(argv[3], "rb");

	if (!keyfile)
	{
		printf("coudlnt open key file");
		return 0;
	}

	mbedtls_aes_init(&aes_ctx);
	mbedtls_md_init(&sha_ctx);

	fread(key, 8, 1, keyfile);

	fwrite(IV, 1, 16, output);

	for (offset = 0; offset < filesize; offset += 16)
	{
		n = (filesize - offset > 16) ? 16 : (int)
			(filesize - offset);

		if (fread(buffer, 1, n, fin) != (size_t)n)
		{
			mbedtls_fprintf(stderr, "fread(%d bytes) failed\n", n);
			goto exit;
		}

		for (i = 0; i < 16; i++)
			buffer[i] = (unsigned char)(buffer[i] ^ IV[i]);

		mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, buffer, buffer);
		mbedtls_md_hmac_update(&sha_ctx, buffer, 16);

		if (fwrite(buffer, 1, 16, fout) != 16)
		{
			mbedtls_fprintf(stderr, "fwrite(%d bytes) failed\n", 16);
			goto exit;
		}

		memcpy(IV, buffer, 16);
	}

}