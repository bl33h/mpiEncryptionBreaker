/*---------------------------------------------------------------------------
Copyright (C), 2024-2025, bl33h, Mendezg1, MelissaPerez09
@author Sara Echeverria, Ricardo Mendez, Melissa Perez
FileName: bruteforce.c
@version: I
Creation: 06/10/2024
Last modification: 08/10/2024
------------------------------------------------------------------------------*/
#include <openssl/des.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define LIGHT_MAGENTA "\x1B[95m"
#define LIGHT_GREEN "\x1B[92m"
#define LIGHT_BLUE "\x1B[94m"
#define YELLOW "\x1B[33m"
#define RESET "\x1B[0m"

typedef struct {
    int code;
    char message[256];
} Error;

void handleError(Error err) {
    if (err.code != 0) {
        fprintf(stderr, LIGHT_MAGENTA "%s\n" RESET, err.message);
        exit(err.code);
    }
}

Error checkFile(FILE* file, const char* filename) {
    Error err = {0, ""};
    if (!file) {
        sprintf(err.message, LIGHT_MAGENTA "!error opening the file: %s.\n" RESET, filename);
        err.code = EXIT_FAILURE;
    }
    return err;
}

Error checkMemory(void* ptr) {
    Error err = {0, ""};
    if (!ptr) {
        sprintf(err.message, LIGHT_MAGENTA "!error allocating memory.\n" RESET);
        err.code = EXIT_FAILURE;
    }
    return err;
}

void encrypt(char* source, char* destiny, DES_key_schedule schedule) {
    for (int i = 0; i < strlen(source); i += 8) {
        char originalSentence[8] = { source[i], source[i + 1], source[i + 2], source[i + 3], source[i + 4], source[i + 5], source[i + 6], source[i + 7] };
        char encryptedSentence[8] = { "" };
        DES_ecb_encrypt((const_DES_cblock*)originalSentence, (DES_cblock*)encryptedSentence, &schedule, DES_ENCRYPT);
        for (int j = 0; j < 8; j++) {
            destiny[i + j] = encryptedSentence[j];
        }
    }
}

void decrypt(char* source, char* destiny, DES_key_schedule schedule) {
    for (int i = 0; i < strlen(source); i += 8) {
        char encryptedSentence[8] = { source[i], source[i + 1], source[i + 2], source[i + 3], source[i + 4], source[i + 5], source[i + 6], source[i + 7] };
        char decryptedSentence[8] = { "" };
        DES_ecb_encrypt((const_DES_cblock*)encryptedSentence, (DES_cblock*)decryptedSentence, &schedule, DES_DECRYPT);
        for (int j = 0; j < 8; j++) {
            destiny[i + j] = decryptedSentence[j];
        }
    }
}

int keysTrial(long keyToTest, char* source, char* searchedText) {
    char stringKey[256];
    sprintf(stringKey, "%ld", keyToTest);
    DES_cblock temporalKeyToTest;
    DES_key_schedule temporalSchedule;
    DES_string_to_key(stringKey, &temporalKeyToTest);
    DES_set_key((const_DES_cblock*)&temporalKeyToTest, &temporalSchedule);
    char temporalText[strlen(source)];
    decrypt(source, temporalText, temporalSchedule);
    return (strstr((char*)temporalText, searchedText) != NULL);
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        handleError((Error){EXIT_FAILURE, LIGHT_MAGENTA "• usage: ./bruteforce <input file name> <key> <search file name>\n\n" RESET});
    }

    char* filePath = argv[1];
    char* inputKey = argv[2];
    char* searchedTextPath = argv[3];
    long upperBound = (1L << 56);

    FILE* inputFile = fopen(filePath, "rb");
    handleError(checkFile(inputFile, filePath));

    fseek(inputFile, 0, SEEK_END);
    long fileLength = ftell(inputFile);
    rewind(inputFile);
    char* inputText = (char*)malloc(fileLength);
    handleError(checkMemory(inputText));

    if (fread(inputText, 1, fileLength, inputFile) != fileLength) {
        handleError((Error){EXIT_FAILURE, LIGHT_MAGENTA "!error reading the file." RESET});
    }

    fclose(inputFile);

    FILE* searchedTextFile = fopen(searchedTextPath, "rb");
    handleError(checkFile(searchedTextFile, searchedTextPath));

    fseek(searchedTextFile, 0, SEEK_END);
    long searchedFileLength = ftell(searchedTextFile);
    rewind(searchedTextFile);
    char* searchedText = (char*)malloc(searchedFileLength);
    handleError(checkMemory(searchedText));

    if (fread(searchedText, 1, searchedFileLength, searchedTextFile) != searchedFileLength) {
        handleError((Error){EXIT_FAILURE, LIGHT_MAGENTA "!error reading the file." RESET});
    }

    fclose(searchedTextFile);
    DES_cblock key;
    DES_key_schedule schedule;
    DES_string_to_key(inputKey, &key);
    DES_set_key((const_DES_cblock*)&key, &schedule);
    char encryptedText[strlen(inputText)];
    char decryptedText[strlen(inputText)];
    encrypt(inputText, encryptedText, schedule);
    long foundKey = 0L;

    for (long i = 0; i < upperBound; i++) {
        if (keysTrial(i, encryptedText, searchedText)) {
            foundKey = i;
            printf(LIGHT_GREEN "\n• the key is: [%ld]\n" RESET, foundKey);
            break;
        }
    }

    DES_key_schedule foundKeySchedule;
    DES_set_key_unchecked((DES_cblock*)&foundKey, &foundKeySchedule);
    decrypt(encryptedText, decryptedText, schedule);
    printf(LIGHT_BLUE "-> original string: %s\n" RESET, inputText);
    printf(YELLOW "!encrypted string: %s\n" RESET, encryptedText);
    decryptedText[(int)strlen(decryptedText) - (int)strlen(encryptedText)] = '\0';
    printf(LIGHT_MAGENTA "\n✓ decrypted string: %s\n" RESET, decryptedText);
    return EXIT_SUCCESS;
}