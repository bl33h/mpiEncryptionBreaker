# MPI Encryption Breaker Project

## Overview
This project implements three approaches to brute-force decrypting a DES-encrypted text. The three approaches include:
1. **Naive (Sequential)**: Performs the search sequentially, testing all possible key combinations until the correct one is found.
2. **First Approach (Parallel with MPI)**: Divides the keyspace among multiple processes using **MPI**, allowing parallel key testing.
3. **Second Approach (Optimized with MPI)**: Improves on the first approach by testing two keys simultaneously in each iteration, reducing the number of iterations needed.

## Requirements
- **GCC**: For compiling the naive approach.
- **MPICC (OpenMPI)**: For compiling the parallel approaches.
- **OpenSSL**: Library to handle DES encryption and decryption.

## Compilation and Execution

### Naive (Sequential Approach):
- **Compilation**:
```bash
gcc -o naive naive.c -lssl -lcrypto
```
- **Execution**:
```bash
./naive <file_to_decrypt> <initial_key> <search_file>
```

### First Approach (Parallel with MPI):
- **Compilation**:
```bash
mpicc -o approach1 firstApproach.c -lssl -lcrypto
```
- **Execution**:
```bash
mpirun --allow-run-as-root -np <number_of_processes> ./approach1 <file_to_decrypt> <initial_key> <search_file>
```

### Second Approach (Optimized MPI):
- **Compilation**:
```bash
mpicc -o approach2 secondApproach.c -lssl -lcrypto
```
- **Execution**:
```bash
mpirun --allow-run-as-root -np <number_of_processes> ./approach2 <file_to_decrypt> <initial_key> <search_file>
```

## Input Files
- **File to decrypt (`string.txt_`):** The file that contains the encrypted text to be decrypted.
- **Search file (`search.txt`):** The file containing the known text to search for within the decrypted text (used as a known substring).

## Results and Execution Time
When executing any of the approaches, the program will print:
1. The correct key used to decrypt the file.
2. The original text and encrypted text.
3. The execution time of the process.

## Report
[Google Docs File](https://docs.google.com/document/d/1gBYKwooIh8LGtv6aTb-s0xYJps8Ycl3qm_3gpTHFJfM/edit?usp=sharing)

## Contributors
[@bl33h](https://github.com/bl33h) | [@MelissaPerez09](https://github.com/MelissaPerez09) | [@Mendezg1](https://github.com/Mendezg1)