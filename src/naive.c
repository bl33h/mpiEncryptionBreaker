/*---------------------------------------------------------------------------
Copyright (C), 2024-2025, bl33h, Mendezg1, MelissaPerez09
@author Sara Echeverria, Ricardo Mendez, Melissa Perez
FileName: naive.c
@version: I
Creation: 08/10/2024
Last modification: 08/10/2024
------------------------------------------------------------------------------*/
#include <openssl/des.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define LIGHT_MAGENTA "\x1B[95m"
#define LIGHT_GREEN "\x1B[92m"
#define LIGHT_BLUE "\x1B[94m"
#define YELLOW "\x1B[33m"
#define RESET "\x1B[0m"

typedef struct {
    char message[256];
    int code;
} ErrorInfo;

void handleError(ErrorInfo errorInfo) {
    fprintf(stderr, LIGHT_MAGENTA "%s\n" RESET, errorInfo.message);
    exit(errorInfo.code);
}

void encrypt(char* source, char* destiny, DES_key_schedule schedule) {
    for (int i = 0; i < strlen(source); i += 8) {
        char originalSentence[8] = { source[i], source[(i + 1)], source[(i + 2)], source[(i + 3)], source[(i + 4)], source[(i + 5)], source[(i + 6)], source[(i + 7)] };
        char encryptedSentence[8] = { "" };
        DES_ecb_encrypt((const_DES_cblock*)originalSentence, (DES_cblock*)encryptedSentence, &schedule, DES_ENCRYPT);
        for (int j = 0; j < 8; j++) {
            destiny[(i + j)] = encryptedSentence[j];
        }
    }
}

void decrypt(char* source, char* destiny, DES_key_schedule schedule) {
    for (int i = 0; i < strlen(source); i += 8) {
        char encryptedSentence[8] = { source[i], source[(i + 1)], source[(i + 2)], source[(i + 3)], source[(i + 4)], source[(i + 5)], source[(i + 6)], source[(i + 7)] };
        char decryptedSentence[8] = { "" };
        DES_ecb_encrypt((const_DES_cblock*)encryptedSentence, (DES_cblock*)decryptedSentence, &schedule, DES_DECRYPT);
        for (int j = 0; j < 8; j++) {
            destiny[(i + j)] = decryptedSentence[j];
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
    clock_t start_time = clock();

    if (argc < 4) {
        ErrorInfo errorInfo = { "• usage: ./naive <input file name> <key> <search file name>", EXIT_FAILURE };
        handleError(errorInfo);
    }

    char* filePath = argv[1];
    char* inputKey = argv[2];
    char* searchedTextPath = argv[3];
    long upperBound = (1L << 56);
    FILE* inputFile = fopen(filePath, "rb");

    if (!inputFile) {
        ErrorInfo errorInfo = { "!error opening the file.", EXIT_FAILURE };
        handleError(errorInfo);
    }

    fseek(inputFile, 0, SEEK_END);
    long fileLength = ftell(inputFile);
    rewind(inputFile);
    char* inputText = (char*)malloc(fileLength);

    if (!inputText) {
        ErrorInfo errorInfo = { "!error allocating memory for the file.", EXIT_FAILURE };
        fclose(inputFile);
        handleError(errorInfo);
    }

    if (fread(inputText, 1, fileLength, inputFile) != fileLength) {
        ErrorInfo errorInfo = { "!error reading the file.", EXIT_FAILURE };
        free(inputText);
        fclose(inputFile);
        handleError(errorInfo);
    }

    fclose(inputFile);
    FILE* searchedTextFile = fopen(searchedTextPath, "rb");

    if (!searchedTextFile) {
        ErrorInfo errorInfo = { "!error opening the search file.", EXIT_FAILURE };
        handleError(errorInfo);
    }

    fseek(searchedTextFile, 0, SEEK_END);
    long searchedFileLength = ftell(searchedTextFile);
    rewind(searchedTextFile);
    char* searchedText = (char*)malloc(searchedFileLength);

    if (!searchedText) {
        ErrorInfo errorInfo = { "!error allocating memory for the search file.", EXIT_FAILURE };
        fclose(searchedTextFile);
        handleError(errorInfo);
    }

    if (fread(searchedText, 1, searchedFileLength, searchedTextFile) != searchedFileLength) {
        ErrorInfo errorInfo = { "!error reading the search file.", EXIT_FAILURE };
        free(searchedText);
        fclose(searchedTextFile);
        handleError(errorInfo);
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
            printf(LIGHT_BLUE "\n• the key is: [%ld]\n" RESET, foundKey);
            break;
        }
    }

    DES_key_schedule foundKeySchedule;
    DES_set_key_unchecked((DES_cblock*)&foundKey, &foundKeySchedule);
    decrypt(encryptedText, decryptedText, schedule);
    printf(LIGHT_MAGENTA "-> original string: %s\n" RESET, inputText);
    printf(LIGHT_GREEN "!encrypted string: %s\n" RESET, encryptedText);
    decryptedText[(int)strlen(decryptedText) - (int)strlen(encryptedText)] = '\0';
    printf(YELLOW "\n✓ decrypted string: %s\n" RESET, decryptedText);
    free(inputText);
    free(searchedText);

    clock_t end_time = clock();
    double time_taken = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("\n✱ execution time: %.2f seconds\n", time_taken);

    return EXIT_SUCCESS;
}