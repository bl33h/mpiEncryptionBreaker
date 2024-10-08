/*---------------------------------------------------------------------------
Copyright (C), 2024-2025, bl33h, Mendezg1, MelissaPerez09
@author Sara Echeverria, Ricardo Mendez, Melissa Perez
FileName: bruteforceNaive.c
@version: I
Creation: 06/10/2024
Last modification: 07/10/2024
------------------------------------------------------------------------------*/
#include <openssl/des.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <omp.h>

#define BLOCK_SIZE 8
#define KEY_LENGTH 56 // Adjusted for DES

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

int tryKey(long keyToTest, const char* source, const char* searchedText, size_t textLength) {
    char stringKey[256];
    snprintf(stringKey, sizeof(stringKey), "%ld", keyToTest);
    DES_cblock key;
    DES_key_schedule schedule;
    DES_string_to_key(stringKey, &key);
    DES_set_key(&key, &schedule);

    char* decryptedText = calloc(textLength + 1, sizeof(char));
    if (!decryptedText) {
        perror("Allocation failed for decrypted text");
        return 0;
    }

    decrypt(source, decryptedText, schedule);
    int found = strstr(decryptedText, searchedText) != NULL;

    // Debugging key attempts
    if (keyToTest % 100000 == 0) {
        printf("Tested key: %ld\n", keyToTest);
    }

    free(decryptedText);
    return found;
}

char* readFile(const char* filePath, long* fileLength) {
    FILE* file = fopen(filePath, "rb");
    if (!file) {
        perror("Error opening the file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *fileLength = ftell(file);
    rewind(file);

    char* buffer = calloc(*fileLength + 1, sizeof(char));
    if (!buffer) {
        perror("Error allocating memory for the file");
        fclose(file);
        return NULL;
    }

    size_t readSize = fread(buffer, 1, *fileLength, file);
    if (readSize < *fileLength) {
        perror("File read error");
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    printf("Read file '%s', size %ld bytes\n", filePath, *fileLength);
    return buffer;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: ./bruteforceNaive <input file name> <key> <search file name>\n");
        return EXIT_FAILURE;
    }

    char* filePath = argv[1];
    char* searchedTextPath = argv[3];
    long fileLength, searchedFileLength;

    char* inputText = readFile(filePath, &fileLength);
    char* searchedText = readFile(searchedTextPath, &searchedFileLength);
    if (!inputText || !searchedText) {
        free(inputText);
        free(searchedText);
        return EXIT_FAILURE;
    }

    long foundKey = -1;
    int keyHasBeenFound = 0;

    #pragma omp parallel for
    for (long i = 0; i < (1L << KEY_LENGTH); i++) {
        if (!keyHasBeenFound && tryKey(i, inputText, searchedText, fileLength)) {
            #pragma omp critical
            {
                if (!keyHasBeenFound) {
                    foundKey = i;
                    keyHasBeenFound = 1;
                    printf("Key found: %ld\n", foundKey);
                }
            }
        }
    }

    if (foundKey != -1) {
        printf("Decrypting with key: %ld\n", foundKey);
        char* decryptedText = calloc(fileLength + 1, sizeof(char));
        if (!decryptedText) {
            perror("Error allocating memory for decrypted text");
            free(inputText);
            free(searchedText);
            return EXIT_FAILURE;
        }

        // Set up the DES schedule with the found key
        DES_cblock key;
        DES_key_schedule schedule;
        char stringKey[256];
        snprintf(stringKey, sizeof(stringKey), "%ld", foundKey);
        DES_string_to_key(stringKey, &key);
        DES_set_key(&key, &schedule);

        // Decrypt the file content
        decrypt(inputText, decryptedText, schedule);
        printf("Decrypted text: %s\n", decryptedText);

        free(decryptedText);
    } else {
        printf("No valid key found.\n");
    }

    free(inputText);
    free(searchedText);
    return EXIT_SUCCESS;
}