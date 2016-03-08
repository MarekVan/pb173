/**
* @file main.cpp
* @author Martin Ukrop
* @licence MIT Licence
*/
#define _CRT_NONSTDC_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include "crypto.h"

// Tell CATCH to define its main function here
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

TEST_CASE("Input -> Encrypt -> Decrypt -> Input", "first") {

	CHECK(encrypt("testFiles/testDataInput1.txt", "testFiles/testDataOutput1.txt", "testFiles/testDataKey1.txt") == 0);
	CHECK(decrypt("testFiles/testDataOutput1.txt", "testFiles/testDataInput1.txt", "testFiles/testDataKey1.txt") == 0);
	
	FILE *input = fopen("testFiles/testDataInput1.txt", "rb");
	FILE *check = fopen("testFiles/testDataCheck1.txt", "rb");

	fseek(input, 0, SEEK_END);
	int filesize = ftell(input);
	rewind(input);
	unsigned char output1[128];
	unsigned char output2[128];

	for (int offset = 0; offset < filesize - filesize % 128; offset += 128)
	{
		fread(output1, sizeof(char), 128, input);
		fread(output1, sizeof(char), 128, check);
		CHECK(memcmp(output1, output2, 128) == 0);
	}

	fread(output1, sizeof(char), filesize % 128, input);
	fread(output1, sizeof(char), filesize % 128, check);
	CHECK(memcmp(output1, output2, filesize % 128) == 0);

	fclose(input);
	fclose(check);
}

TEST_CASE("File doesnt exist", "second") {
	CHECK(encrypt("thisdoesntexist.txt", "someting.txt", "testDataKey1") == 1);
	CHECK(decrypt("thisdoesntexist.txt", "someting.txt", "testDataKey1") == 1);
}

TEST_CASE("File was corrupted", "third") {
	CHECK(decrypt("testFiles/CorruptedInput.txt", "testFiles/someting.txt", "testFiles/testDataKey1") == 5);
}

TEST_CASE("Wrong key", "fourth") {
	CHECK(decrypt("testFiles/testDataInput1.txt", "testFiles/testDataOutput1.txt", "testFiles/WrongKey.txt") == 6);
}

TEST_CASE("Test vector 1", "fifth") {
	CHECK(decrypt("testFiles/testVectorInput1.txt", "testFiles/testVectorOutput1.txt", "testFiles/testVectorKey1.txt") == 0);

	FILE *input = fopen("testFiles/testVectorOutput1.txt", "rb");
	FILE *check = fopen("testFiles/testVectorCheck1.txt", "rb");
	rewind(input);
	fseek(input, 0, SEEK_END);
	int filesize = ftell(input);
	rewind(input);
	unsigned char output1[128];
	unsigned char output2[128];

	for (int offset = 0; offset < filesize - filesize % 128; offset += 128)
	{
		fread(output1, sizeof(char), 128, input);
		fread(output1, sizeof(char), 128, check);
		CHECK(memcmp(output1, output2, 128) == 0);
	}

	fread(output1, sizeof(char), filesize % 128, input);
	fread(output1, sizeof(char), filesize % 128, check);
	CHECK(memcmp(output1, output2, filesize % 128) == 0);

	fclose(input);
	fclose(check);
}

TEST_CASE("Test vector 2", "sixth") {
	CHECK(decrypt("testFiles/testVectorInput2.txt", "testFiles/testVectorOutput2.txt", "testFiles/testVectorKey2.txt") == 0);

	FILE *input = fopen("testFiles/testVectorOutput2.txt", "rb");
	FILE *check = fopen("testFiles/testVectorCheck2.txt", "rb");
	rewind(input);
	fseek(input, 0, SEEK_END);
	int filesize = ftell(input);
	rewind(input);
	unsigned char output1[128];
	unsigned char output2[128];

	for (int offset = 0; offset < filesize - filesize % 128; offset += 128)
	{
		fread(output1, sizeof(char), 128, input);
		fread(output1, sizeof(char), 128, check);
		CHECK(memcmp(output1, output2, 128) == 0);
	}

	fread(output1, sizeof(char), filesize % 128, input);
	fread(output1, sizeof(char), filesize % 128, check);
	CHECK(memcmp(output1, output2, filesize % 128) == 0);

	fclose(input);
	fclose(check);
}