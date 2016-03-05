/**
* @file main.cpp
* @author Martin Ukrop
* @licence MIT Licence
*/
#define _CRT_NONSTDC_NO_WARNINGS
#include "main.cpp"

// Tell CATCH to define its main function here
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

TEST_CASE("Encrypt -> Decrypt testing", "") {
	FILE *input = fopen("testDataInput1", "br+");
	FILE *output = fopen("testDataOutput1", "bw+");
	FILE *check = fopen("testDataCheck1", "br");
	unsigned char key[16] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P'};
	unsigned char IV[16]= { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	encrypt(input, output, key, IV);
	decrypt(output, input, key);

	rewind(input);
	fseek(input, 0, SEEK_END);
	int filesize = ftell(input);
	rewind(input);
	unsigned char output1[128];
	unsigned char output2[128];

	for (int offset = 0; offset < filesize - filesize % 128; offset += 128)
	{
		fread(output1, 1, 128, input);
		fread(output1, 1, 128, check);
		CHECK("Comparing outputs", memcmp(output1, output2, 128) == 0);
	}

	fread(output1, 1, filesize % 128, input);
	fread(output1, 1, filesize % 128, check);
	CHECK("Comparing outputs", memcmp(output1, output2, filesize % 128) == 0);

	fclose(input);
	fclose(output);
	fclose(check);
}