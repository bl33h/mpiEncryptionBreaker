/*---------------------------------------------------------------------------
Copyright (C), 2024-2025, bl33h, Mendezg1, MelissaPerez09
@author Sara Echeverria, Ricardo Mendez, Melissa Perez
FileName: firstApproach.c
@version: II (previously called parallelVersion.c)
Creation: 08/10/2024
Last modification: 09/10/2024
------------------------------------------------------------------------------*/
#include <openssl/des.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <mpi.h>

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
        ErrorInfo errorInfo = { "• usage: ./approach1 <input file name> <key> <search file name>", EXIT_FAILURE };
        handleError(errorInfo);
    }

    char* filePath = argv[1];
    char* inputKey = argv[2];
    char* searchedTextPath = argv[3];
    int threads, rank;
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
  
    MPI_Init(NULL, NULL);
    MPI_Status status;
    MPI_Request request;
    MPI_Comm_size(MPI_COMM_WORLD, &threads);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    long foundKey = 0L;
    int keyHasBeenFound = 0;
    long boundPerThread = (upperBound / threads);
    long localLowerBound = (boundPerThread * rank);
    long localUpperBound = ((boundPerThread * (rank + 1)) - 1);
    if (rank == (threads - 1)) {
        localUpperBound = upperBound;
    }
    MPI_Irecv(&foundKey, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &request);
  
    time_t startTime = time(NULL);

    for (long i = localLowerBound; i < localUpperBound; i++) {
        MPI_Test(&request, &keyHasBeenFound, MPI_STATUS_IGNORE);
        if (keyHasBeenFound) break;
        if (keysTrial(i, encryptedText, searchedText)) {
            foundKey = i;
            printf(LIGHT_GREEN "\n• the key is: [%ld]\n" RESET, foundKey);
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
        printf(YELLOW "-> original string: %s\n" RESET, inputText);
        printf(LIGHT_BLUE "!encrypted string: %s\n" RESET, encryptedText);
        decryptedText[(int)strlen(decryptedText) - (int)strlen(encryptedText)] = '\0';
        printf(LIGHT_MAGENTA "\n✓ decrypted string: %s\n" RESET, decryptedText);
        time_t endTime = time(NULL);
        double timeTaken = difftime(endTime, startTime);
        printf("\n✱ total execution time: %.2f seconds\n", timeTaken);
    }

    free(inputText);
    free(searchedText);
    MPI_Finalize();
    return EXIT_SUCCESS;
}