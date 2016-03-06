/**
* @file main.cpp
* @author Martin Ukrop
* @licence MIT Licence
*/
#define _CRT_NONSTDC_NO_WARNINGS
#include "crypto.h"

// Tell CATCH to define its main function here
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

TEST_CASE("Input -> Encrypt -> Decrypt -> Input", "first") {
	CHECK("Encryption should be succesfull", encrypt("testDataInput1", "testDataOutput1", "testDataKey1") == 0);
	CHECK("Decryption should be succesfull", decrypt("testDataOutput1", "testDataInput1", "testDataKey1") == 0);
	
	FILE *input = fopen("testDataInput1.txt", "br");
	FILE *check = fopen("testDataCheck1.txt", "br");
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
		CHECK("Outputs should be equal", memcmp(output1, output2, 128) == 0);
	}

	fread(output1, 1, filesize % 128, input);
	fread(output1, 1, filesize % 128, check);
	CHECK("Outputs should be equal", memcmp(output1, output2, filesize % 128) == 0);

	fclose(input);
	fclose(output);
	fclose(check);
}

TEST_CASE("File doesnt exist", "second") {
	CHECK("Encryption should return  1", encrypt("thisdoesntexist.txt", "someting.txt", "testDataKey1") == 1);
	CHECK("Decryption should return  1", decrypt("thisdoesntexist.txt", "someting.txt", "testDataKey1") == 1);
}

TEST_CASE("File was corrupted", "third") {
	CHECK("Decryption should return  5", decrypt("CorruptedInput.txt", "someting.txt", "testDataKey2") == 5);
}

TEST_CASE("Wrong key", "fourth") {
	CHECK("Decryption should return  6", decrypt("testDataInput1.txt", "testDataOutput1.txt", "WrongKey.txt") == 6);
}

TEST_CASE("Test vector 1", "fifth") {
	CHECK("Encryption should return  0", decrypt("testVectorInput1.txt", "testVectorOutput1.txt", "testVectorKey1.txt") == 0);

	FILE *input = fopen("testVectorOutput1.txt", "br");
	FILE *check = fopen("testVectorCheck1.txt", "br");
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
		CHECK("Outputs should be equal", memcmp(output1, output2, 128) == 0);
	}

	fread(output1, 1, filesize % 128, input);
	fread(output1, 1, filesize % 128, check);
	CHECK("Outputs should be equal", memcmp(output1, output2, filesize % 128) == 0);

	fclose(input);
	fclose(output);
	fclose(check);
}

TEST_CASE("Test vector 2", "sixth") {
	CHECK("Encryption should return  0", decrypt("testVectorInput2.txt", "testVectorOutput2.txt", "testVectorKey2.txt") == 0);

	FILE *input = fopen("testVectorOutput2.txt", "br");
	FILE *check = fopen("testVectorCheck2.txt", "br");
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
		CHECK("Outputs should be equal", memcmp(output1, output2, 128) == 0);
	}

	fread(output1, 1, filesize % 128, input);
	fread(output1, 1, filesize % 128, check);
	CHECK("Outputs should be equal", memcmp(output1, output2, filesize % 128) == 0);

	fclose(input);
	fclose(output);
	fclose(check);
}