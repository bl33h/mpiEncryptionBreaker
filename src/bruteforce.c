/*---------------------------------------------------------------------------
Copyright (C), 2024-2025, bl33h, Mendezg1, MelissaPerez09
@author Sara Echeverria, Ricardo Mendez, Melissa Perez
FileName: bruteforce.c
@version: I
Creation: 06/10/2024
Last modification: 07/10/2024
------------------------------------------------------------------------------*/

#include <openssl/des.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define BLOCK_SIZE 8
#define KEY_LENGTH 56

void process(const char* source, char* destiny, DES_key_schedule schedule, int mode) {
    for (size_t i = 0; i < strlen(source); i += BLOCK_SIZE) {
        char block[BLOCK_SIZE] = {0};
        memcpy(block, source + i, BLOCK_SIZE);
        char processedBlock[BLOCK_SIZE] = {0};
        DES_ecb_encrypt((const_DES_cblock*)block, (DES_cblock*)processedBlock, &schedule, mode);
        memcpy(destiny + i, processedBlock, BLOCK_SIZE);
    }
}

void encrypt(const char* source, char* destiny, DES_key_schedule schedule) {
    process(source, destiny, schedule, DES_ENCRYPT);
}

void decrypt(const char* source, char* destiny, DES_key_schedule schedule) {
    process(source, destiny, schedule, DES_DECRYPT);
}

int tryKey(long keyToTest, const char* source, const char* searchedText) {
    char stringKey[256];
    snprintf(stringKey, sizeof(stringKey), "%ld", keyToTest);
    DES_cblock temporalKeyToTest;
    DES_key_schedule temporalSchedule;
    DES_string_to_key(stringKey, &temporalKeyToTest);
    DES_set_key((const_DES_cblock*)&temporalKeyToTest, &temporalSchedule);
    
    size_t textLength = strlen(source);
    char* temporalText = (char*)calloc(textLength + 1, sizeof(char));
    if (!temporalText) {
        perror("!error allocating memory for temporary text.\n");
        return 0;
    }

    decrypt(source, temporalText, temporalSchedule);
    int found = (strstr(temporalText, searchedText) != NULL);
    free(temporalText);
    return found;
}

char* readFile(const char* filePath, long* fileLength) {
    FILE* file = fopen(filePath, "rb");
    if (!file) {
        perror("!error opening the file.\n");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *fileLength = ftell(file);
    rewind(file);

    char* buffer = (char*)calloc(*fileLength + 1, sizeof(char));
    if (!buffer) {
        perror("!error allocating memory for the file.\n");
        fclose(file);
        return NULL;
    }

    if (fread(buffer, 1, *fileLength, file) != *fileLength) {
        perror("!error reading the file.\n");
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return buffer;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "• usage: ./naivePar <input file name> <key> <search file name>\n");
        return EXIT_FAILURE;
    }

    char* filePath = argv[1];
    char* inputKey = argv[2];
    char* searchedTextPath = argv[3];
    long upperBound = (1L << KEY_LENGTH);
    long fileLength, searchedFileLength;

    char* inputText = readFile(filePath, &fileLength);
    if (!inputText) return EXIT_FAILURE;

    char* searchedText = readFile(searchedTextPath, &searchedFileLength);
    if (!searchedText) {
        free(inputText);
        return EXIT_FAILURE;
    }

    DES_cblock key;
    DES_key_schedule schedule;
    DES_string_to_key(inputKey, &key);
    DES_set_key((const_DES_cblock*)&key, &schedule);

    char* encryptedText = (char*)calloc(fileLength + 1, sizeof(char));
    if (!encryptedText) {
        perror("!error allocating memory for encrypted text.\n");
        free(inputText);
        free(searchedText);
        return EXIT_FAILURE;
    }

    encrypt(inputText, encryptedText, schedule);
    long foundKey = 0L;
    int keyHasBeenFound = 0;

    for (long i = 0; i < upperBound; i++) {
        if (tryKey(i, encryptedText, searchedText)) {
            foundKey = i;
            printf("\n• key: %ld\n", foundKey);
            keyHasBeenFound = 1;
            break;
        }
    }

    if (keyHasBeenFound) {
        DES_key_schedule foundKeySchedule;
        DES_set_key_unchecked((DES_cblock*)&foundKey, &foundKeySchedule);

        char* decryptedText = (char*)calloc(fileLength + 1, sizeof(char));
        if (!decryptedText) {
            perror("!error allocating memory for decrypted text.\n");
            free(inputText);
            free(searchedText);
            free(encryptedText);
            return EXIT_FAILURE;
        }

        decrypt(encryptedText, decryptedText, foundKeySchedule);
        printf("-> original text: %s\n", inputText);
        printf("✓ encrypted text: %s\n", encryptedText);
        printf("✓ decrypted text: %s\n", decryptedText);

        free(decryptedText);
    } else {
        printf("!error, key not found.\n");
    }

    free(inputText);
    free(searchedText);
    free(encryptedText);
    return EXIT_SUCCESS;
}