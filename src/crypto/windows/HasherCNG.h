#ifndef SHARED_HASHER_CNG_H
#define SHARED_HASHER_CNG_H

#include <windows.h>
#include <bcrypt.h>

#include <stdint.h>

//#define MD5_STRING_LN (0x20)
//#define MD5_STRING_BUFFER_LN (0x21)

#define SHA1_BYTES_LN (0x14)
#define SHA1_STRING_LN (0x28)
#define SHA1_STRING_BUFFER_LN (0x29)

#define SHA256_BYTES_LN (0x20)
#define SHA256_STRING_LN (0x40)
#define SHA256_STRING_BUFFER_LN (0x41)


typedef struct Sha256Ctxt {
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_HASH_HANDLE hash;
    NTSTATUS status;
    DWORD data_size;
    DWORD hash_size;
    DWORD hash_object_size;
    PBYTE hash_object;
} Sha256Ctxt, * PSha256Ctxt;


int initSha256(PSha256Ctxt ctxt);

int cleanSha256(PSha256Ctxt ctxt);


/**
 * Create sha256 hash of a given file.
 * Using a FILE* to open the file.
 *
 * @param   path char* the input file path
 * @param   hash_bytes unsigned char* The input hash bytes
 * @param   hash_size DWORD Size of the hash_bytes.
 * @return  int the success state
 */
int sha256File(
    const char* path, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size
);


/**
 * Create sha256 hash of a given file.
 * Using a FILE* to open the file.
 *
 * @param   path char* the input file path
 * @param   hash_bytes unsigned char* The input hash bytes
 * @param   hash_size DWORD Size of the hash_bytes.
 * @return  ctxt PSha256Ctxt initialized Sha256Ctxt
 * @return  int the success state
 */
int sha256FileC(
    const char* path, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size, 
    PSha256Ctxt ctxt
);

int sha256Buffer(
    uint8_t* buffer, 
    uint32_t buffer_ln, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size
);

int sha256BufferC(
    uint8_t* buffer, 
    uint32_t buffer_ln, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size, 
    PSha256Ctxt ctxt
);

/**
 * Convert hash bytes to ascii string.
 *
 * @param   hash unsigned char* The input hash bytes
 * @param   hash_size uint16_t Size of the hash_bytes.
 * @param   output char* The output hash string
 * @param   output_size uint16_t The outout buffer size. Should be at least hash_size*2 + 1.
 */
void hashToString(
    const unsigned char* hash, 
    uint16_t hash_size, 
    char* output, 
    uint16_t output_size
);

/**
 * Print the hash to stdout.
 *
 * @param   hash unsigned char* The input hash bytes
 * @param   hash_size uint16_t Size of the hash_bytes.
 * @param   prefix char* A Prefix.
 * @param   postfix char* A Postfix.
 */
void printHash(
    const unsigned char* hash, 
    uint16_t hash_size, 
    const char* prefix, 
    const char* postfix
);

#endif
