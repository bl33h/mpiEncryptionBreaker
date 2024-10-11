/*---------------------------------------------------------------------------
Copyright (C), 2024-2025, bl33h, Mendezg1, MelissaPerez09
@author Sara Echeverria, Ricardo Mendez, Melissa Perez
FileName: secondApproach.c
@version: I
Creation: 10/10/2024
Last modification: 10/10/2024
------------------------------------------------------------------------------*/
#include <openssl/des.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <mpi.h>

//--- color codes ---
#define LIGHT_MAGENTA "\x1B[95m"
#define LIGHT_GREEN "\x1B[92m"
#define LIGHT_BLUE "\x1B[94m"
#define YELLOW "\x1B[33m"
#define RESET "\x1B[0m"

// --- encryption function ---
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

// --- decryption function ---
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

// --- first and last keys checker ---
int duoKeyTry(long firstKeyToTest, long secondKeyToTest, char* source, char* searchedText) {
    char firstStringKey[256];
    sprintf(firstStringKey, "%ld", firstKeyToTest);
    DES_cblock firstTemporalKeyToTest;
    DES_key_schedule firstTemporalSchedule;
    DES_string_to_key(firstStringKey, &firstTemporalKeyToTest);
    DES_set_key((const_DES_cblock*)&firstTemporalKeyToTest, &firstTemporalSchedule);
    char firstTemporalText[strlen(source)];
    decrypt(source, firstTemporalText, firstTemporalSchedule);
    
    char secondStringKey[256];
    sprintf(secondStringKey, "%ld", secondKeyToTest);
    DES_cblock secondTemporalKeyTest;
    DES_key_schedule secondTemporalSchedule;
    DES_string_to_key(secondStringKey, &secondTemporalKeyTest);
    DES_set_key((const_DES_cblock*)&secondTemporalKeyTest, &secondTemporalSchedule);
    char secondTemporalText[strlen(source)];
    decrypt(source, secondTemporalText, secondTemporalSchedule);
    
    if (strstr(firstTemporalText, searchedText) != NULL) {
        return firstKeyToTest;
    } else if (strstr(secondTemporalText, searchedText) != NULL) {
        return secondKeyToTest;
    } else {
        return 0;
    }
}

// --- main function ---
int main(int argc, char* argv[]) {
    if (argc < 4) {
        perror("• usage: mpirun --allow-run-as-root -np 4 ./approach2 <input file name> <key> <search file name>\n");
        return EXIT_FAILURE;
    }
    char* filePath = argv[1];
    char* inputKey = argv[2];
    char* searchedTextPath = argv[3];
    int threads, rank;
    long upperBound = (1L << 56);

    FILE* inputFile = fopen(filePath, "rb");
    if (!inputFile) {
        perror("!error opening the file.\n");
        return EXIT_FAILURE;
    }

    fseek(inputFile, 0, SEEK_END);
    long fileLength = ftell(inputFile);
    rewind(inputFile);
    char* inputText = (char*)malloc(fileLength);

    if (!inputText) {
        perror("!error allocating memory for the file.\n");
        fclose(inputFile);
        return EXIT_FAILURE;
    }

    if (fread(inputText, 1, fileLength, inputFile) != fileLength) {
        perror("!error reading the file.\n");
        free(inputText);
        fclose(inputFile);
        return EXIT_FAILURE;
    }

    fclose(inputFile);
    
    FILE* searchedTextFile = fopen(searchedTextPath, "rb");
    if (!searchedTextFile) {
        perror("!error opening the search file.\n");
        return EXIT_FAILURE;
    }

    fseek(searchedTextFile, 0, SEEK_END);
    long searchedFileLength = ftell(searchedTextFile);
    rewind(searchedTextFile);
    char* searchedText = (char*)malloc(searchedFileLength);

    if (!searchedText) {
        perror("!error allocating memory for the search file.\n");
        fclose(searchedTextFile);
        return EXIT_FAILURE;
    }

    if (fread(searchedText, 1, searchedFileLength, searchedTextFile) != searchedFileLength) {
        perror("!error reading the search file.\n");
        free(searchedText);
        fclose(searchedTextFile);
        return EXIT_FAILURE;
    }

    fclose(searchedTextFile);
    
    // --- key setup ---
    DES_cblock key;
    DES_key_schedule schedule;
    DES_string_to_key(inputKey, &key);
    DES_set_key((const_DES_cblock*)&key, &schedule);
    
    // encryption
    char encryptedText[strlen(inputText)];
    char decryptedText[strlen(inputText)];
    encrypt(inputText, encryptedText, schedule);
    
    // mpi setup
    MPI_Init(NULL, NULL);
    MPI_Status status;
    MPI_Request request;
    MPI_Comm_size(MPI_COMM_WORLD, &threads);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    
    // --- key search ---
    long foundKey = 0L;
    int keyHasBeenFound = 0;
    long boundPerThread = (upperBound / threads);
    long localLowerBound = (boundPerThread * rank);
    long localUpperBound = ((boundPerThread * (rank + 1)) - 1);
    if (rank == (threads - 1)) {
        localUpperBound = upperBound;
    }

    MPI_Irecv(&foundKey, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &request);

    // --- timer ---
    clock_t startTime = clock();
    
    for (long i = 0; i < (((localUpperBound - localLowerBound) / 2) + 1); i++) {
        MPI_Test(&request, &keyHasBeenFound, MPI_STATUS_IGNORE);

        if (keyHasBeenFound) break;

        long response = duoKeyTry((localLowerBound + i), (localUpperBound - i), encryptedText, searchedText);
        
        if (response > 0) {
            foundKey = response;
            printf(LIGHT_MAGENTA "\n• the key is: [%ld]\n" RESET, foundKey);
            for (int node = 0; node < threads; node++) {
                MPI_Send(&foundKey, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
            }
            break;
        }
    }

    if (rank == 0) {
        MPI_Wait(&request, &status);
        DES_key_schedule foundKeySchedule;
        DES_set_key_unchecked((DES_cblock*)&foundKey, &foundKeySchedule);
        decrypt(encryptedText, decryptedText, schedule);
        printf(LIGHT_GREEN "-> original string: %s\n" RESET, inputText);
        printf(YELLOW "!encrypted string: %s\n" RESET, encryptedText);
        decryptedText[(int)strlen(decryptedText) - (int)strlen(encryptedText)] = '\0';
        printf(LIGHT_BLUE "\n✓ decrypted string: %s\n" RESET, decryptedText);
    }
    
    clock_t endTime = clock();
    double timeTaken = ((double)(endTime - startTime)) / CLOCKS_PER_SEC;
    if (rank == 0) {
        printf("\n✱ total execution time: %.2f seconds\n", timeTaken);
    }

    MPI_Finalize();
    return EXIT_SUCCESS;
}