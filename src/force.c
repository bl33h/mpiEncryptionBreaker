#include <openssl/des.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <mpi.h>
#include <time.h>


#define SEARCH_STRING "this is a testing string"
#define FILE_NAME_ENCRYPTED "encrypted.txt"
#define FILE_NAME_DECRYPTED "decrypted.txt"
#define FILE_NAME_INPUT "input.txt"
#define MAX_KEY_LENGTH (1L << 56)

void handleError(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}

void crypt(long key, char *data, int length, int isEncrypt) {
    DES_cblock keyBlock;
    DES_key_schedule schedule;

    memset(keyBlock, 0, sizeof(DES_cblock));
    memcpy(keyBlock, &key, sizeof(long));
    DES_set_key_unchecked(&keyBlock, &schedule);

    for (int i = 0; i < length; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(data + i), (DES_cblock *)(data + i), &schedule, isEncrypt);
    }
}

int containsSearchString(const char *text) {
    return strstr(text, SEARCH_STRING) != NULL;
}

int tryKey(long key, char *cipherText, int length) {
    char *temp = malloc(length + 1);
    if (!temp) return 0;

    memcpy(temp, cipherText, length);
    temp[length] = '\0';
    crypt(key, temp, length, 0); // 0 for decryption

    int found = containsSearchString(temp);
    if (found) {
        printf("Key found: %li\n", key);
    }

    free(temp);
    return found;
}

int loadTextFromFile(const char *filename, char **text, int *length) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        handleError("Error opening file");
    }

    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    fseek(file, 0, SEEK_SET);

    *text = malloc(*length);
    if (!*text) {
        handleError("Memory allocation error");
    }

    fread(*text, 1, *length, file);
    fclose(file);
    return 1;
}

int saveTextToFile(const char *filename, char *text, int length) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        handleError("Error opening file");
    }

    fwrite(text, 1, length, file);
    fclose(file);
    return 1;
}

void processCommandLineArguments(int argc, char *argv[], long *encryptionKey) {
    int option;
    while ((option = getopt(argc, argv, "k:")) != -1) {
        if (option == 'k') {
            *encryptionKey = atol(optarg);
        } else {
            fprintf(stderr, "Usage: %s [-k key]\n", argv[0]);
            MPI_Finalize();
            exit(EXIT_FAILURE);
        }
    }
}

void calculateKeyRange(int totalProcesses, int currentRank, long *lowerBound, long *upperBound) {
    long rangePerNode = MAX_KEY_LENGTH / totalProcesses;
    *lowerBound = rangePerNode * currentRank;
    *upperBound = (currentRank == totalProcesses - 1) ? MAX_KEY_LENGTH : rangePerNode * (currentRank + 1);
}

void initializeText(MPI_Comm comm, int rank, long key, char **text, int *textLength) {
    if (rank == 0) {
        if (!loadTextFromFile(FILE_NAME_INPUT, text, textLength)) {
            MPI_Finalize();
            exit(EXIT_FAILURE);
        }

        crypt(key, *text, *textLength, 1); // 1 for encryption
        if (!saveTextToFile(FILE_NAME_ENCRYPTED, *text, *textLength)) {
            free(*text);
            MPI_Finalize();
            exit(EXIT_FAILURE);
        }
    }

    MPI_Bcast(textLength, 1, MPI_INT, 0, comm);
    if (rank != 0) {
        *text = malloc(*textLength);
    }
    MPI_Bcast(*text, *textLength, MPI_CHAR, 0, comm);
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);

    int totalProcesses, currentRank;
    MPI_Comm_size(MPI_COMM_WORLD, &totalProcesses);
    MPI_Comm_rank(MPI_COMM_WORLD, &currentRank);

    long encryptionKey = 123456L;
    processCommandLineArguments(argc, argv, &encryptionKey);

    clock_t startClock = clock();
    double startTime = MPI_Wtime();

    long myLowerBound, myUpperBound;
    calculateKeyRange(totalProcesses, currentRank, &myLowerBound, &myUpperBound);

    char *text = NULL;
    int textLength = 0;
    initializeText(MPI_COMM_WORLD, currentRank, encryptionKey, &text, &textLength);

    long foundKey = 0;
    MPI_Request request;
    MPI_Irecv(&foundKey, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &request);

    for (long key = myLowerBound; key < myUpperBound && foundKey == 0; ++key) {
        if (tryKey(key, text, textLength)) {
            foundKey = key;
            for (int node = 0; node < totalProcesses; node++) {
                MPI_Send(&foundKey, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
            }
            break;
        }
    }

    if (currentRank == 0) {
        MPI_Wait(&request, MPI_STATUS_IGNORE);
        crypt(foundKey, text, textLength, 0); // 0 for decryption

        double endTime = MPI_Wtime();
        clock_t endClock = clock();

        printf("MPI execution time: %f seconds\n", endTime - startTime);
        printf("Execution time: %f seconds\n", (double)(endClock - startClock) / CLOCKS_PER_SEC);

        if (!saveTextToFile(FILE_NAME_DECRYPTED, text, textLength)) {
            free(text);
            MPI_Finalize();
            exit(EXIT_FAILURE);
        }
    }

    free(text);
    MPI_Finalize();
    return EXIT_SUCCESS;
}