#pragma warning( disable : 4996 )

#include <stdio.h>

#include "HasherCNG.h"
#include "../../files/Files.h"
#include "../../winDefs.h"


#define BUFFER_SIZE (0x1000)



static int createHash(
    PHashCtxt ctxt
);

__forceinline
int hashData(
    UCHAR* buffer,
    size_t to_read,
    size_t offset,
    FILE* fp, 
    PHashCtxt ctxt
)
{
    size_t bytes_read;
    int errsv;
    int status = 0;

    (offset);
    //fseek(fp, SEEK_SET, offset);

    errno = 0;
    bytes_read = fread(buffer, 1, to_read, fp);
    errsv = errno;
    if ( (bytes_read == 0 || bytes_read != to_read) && errsv != 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%x): Reading bytes failed!\n", errsv);
#endif
        status = 10;
        goto clean;
    }

    status = BCryptHashData(ctxt->hash, buffer, (ULONG)bytes_read, 0);
    if (!NT_SUCCESS(status))
    {
#ifdef ERROR_PRINT
        printf("Error 0x%x returned by BCryptHashData\n", status);
#endif
        status = 8;
        goto clean;
    }
clean:
    ;

    return status;
}

int hashFileC(const char* path, unsigned char* hash_bytes, uint16_t hash_bytes_size, PHashCtxt ctxt)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    FILE* fp = NULL;
    size_t file_size = 0;
    UCHAR buffer[BUFFER_SIZE];
    size_t offset = 0;
    int s = 0;
    size_t parts;
    size_t rest;
    size_t i;

    if ( hash_bytes_size < ctxt->hash_size )
    {
        s = 9;
        goto clean;
    }

    s = createHash(ctxt);
    if ( s != 0 )
    {
        s = 8;
        goto clean;
    }

    fp = fopen(path, "rb");
    if ( !fp )
    {
#ifdef ERROR_PRINT
        printf("ERROR: Could not open file \"%s\"!\n", path);
#endif
        s = 7;
        goto clean;
    }

    s = getFileSize(path, &file_size);
    if ( s != 0 )
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%x): getFileSize \"%s\"!\n", s, path);
#endif
        s = 10;
        goto clean;
    }

    parts = file_size / BUFFER_SIZE;
    rest = file_size % BUFFER_SIZE;
    i;
    for ( i = 0; i < parts; i++ )
    {
        s = hashData(buffer, BUFFER_SIZE, offset, fp, ctxt);
        if ( !NT_SUCCESS(s) )
        {
#ifdef ERROR_PRINT
            printf("Error 0x%x returned by BCryptHashData\n", status);
#endif
            s = 8;
            goto clean;
        }

        offset += BUFFER_SIZE;
    }
    if ( rest != 0 )
    {
        s = hashData(buffer, rest, offset, fp, ctxt);
        if ( !NT_SUCCESS(s) )
        {
#ifdef ERROR_PRINT
            printf("Error 0x%x returned by BCryptHashData\n", status);
#endif
            s = 8;
            goto clean;
        }
    }

    // close the hash
    status = BCryptFinishHash(ctxt->hash, hash_bytes, ctxt->hash_size, 0);
    if (!NT_SUCCESS(status))
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptFinishHash\n", status);
#endif
        s = 9;
        goto clean;
    }

clean:
    if (fp)
    {
        fclose(fp);
    }

    return s;
}

int hashBufferC(
    uint8_t* buffer, 
    uint32_t buffer_ln, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size, 
    PHashCtxt ctxt
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    int s = 0;

    if ( hash_bytes_size < ctxt->hash_size )
    {
        s = 9;
        goto clean;
    }

    s = createHash(ctxt);
    if ( s != 0 )
    {
        s = 8;
        goto clean;
    }

    status = BCryptHashData(ctxt->hash, buffer, (ULONG)buffer_ln, 0);
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error 0x%x returned by BCryptHashData\n", status);
#endif
        s = 8;
        goto clean;
    }

    // close the hash
    status = BCryptFinishHash(ctxt->hash, hash_bytes, ctxt->hash_size, 0);
    if ( !NT_SUCCESS(status) )
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptFinishHash\n", status);
#endif
        s = 9;
        goto clean;
    }

clean:
    ;

    return s;
}


int sha256File(const char* path, unsigned char* hash_bytes, uint16_t hash_bytes_size)
{
    Sha256Ctxt ctxt;
    int s = 0;

    s = initSha256(&ctxt);
    if ( s != 0 )
    {
        goto clean;
    }

    s = sha256FileC(path, hash_bytes, hash_bytes_size, &ctxt);

clean:
    cleanSha256(&ctxt);

    return s;
}

int sha256FileC(const char* path, unsigned char* hash_bytes, uint16_t hash_bytes_size, PSha256Ctxt ctxt)
{
    return hashFileC(path, hash_bytes, hash_bytes_size, ctxt);
}

int sha256Buffer(
    uint8_t* buffer, 
    uint32_t buffer_ln, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size
)
{
    Sha256Ctxt ctxt;
    int s = 0;

    s = initSha256(&ctxt);
    if ( s != 0 )
    {
        goto clean;
    }

    s = sha256BufferC(buffer, buffer_ln, hash_bytes, hash_bytes_size, &ctxt);

clean:
    cleanSha256(&ctxt);

    return s;
}

int sha256BufferC(
    uint8_t* buffer, 
    uint32_t buffer_ln, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size, 
    PSha256Ctxt ctxt
)
{
    return hashBufferC(buffer, buffer_ln, hash_bytes, hash_bytes_size, ctxt);
}

int sha1File(const char* path, unsigned char* hash_bytes, uint16_t hash_bytes_size)
{
    Sha1Ctxt ctxt;
    int s = 0;

    s = initSha1(&ctxt);
    if ( s != 0 )
    {
        goto clean;
    }

    s = sha1FileC(path, hash_bytes, hash_bytes_size, &ctxt);

clean:
    cleanSha1(&ctxt);

    return s;
}

int sha1FileC(const char* path, unsigned char* hash_bytes, uint16_t hash_bytes_size, PSha1Ctxt ctxt)
{
    return hashFileC(path, hash_bytes, hash_bytes_size, ctxt);
}

int sha1Buffer(
    uint8_t* buffer, 
    uint32_t buffer_ln, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size
)
{
    Sha1Ctxt ctxt;
    int s = 0;

    s = initSha1(&ctxt);
    if ( s != 0 )
    {
        goto clean;
    }

    s = sha1BufferC(buffer, buffer_ln, hash_bytes, hash_bytes_size, &ctxt);

clean:
    cleanSha1(&ctxt);

    return s;
}

int sha1BufferC(
    uint8_t* buffer, 
    uint32_t buffer_ln, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size, 
    PSha1Ctxt ctxt
)
{
    return hashBufferC(buffer, buffer_ln, hash_bytes, hash_bytes_size, ctxt);
}

int md5File(const char* path, unsigned char* hash_bytes, uint16_t hash_bytes_size)
{
    Md5Ctxt ctxt;
    int s = 0;

    s = initMd5(&ctxt);
    if ( s != 0 )
    {
        goto clean;
    }

    s = md5FileC(path, hash_bytes, hash_bytes_size, &ctxt);

clean:
    cleanMd5(&ctxt);

    return s;
}

int md5FileC(const char* path, unsigned char* hash_bytes, uint16_t hash_bytes_size, PMd5Ctxt ctxt)
{
    return hashFileC(path, hash_bytes, hash_bytes_size, ctxt);
}

int md5Buffer(
    uint8_t* buffer, 
    uint32_t buffer_ln, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size
)
{
    Md5Ctxt ctxt;
    int s = 0;

    s = initMd5(&ctxt);
    if ( s != 0 )
    {
        goto clean;
    }

    s = md5BufferC(buffer, buffer_ln, hash_bytes, hash_bytes_size, &ctxt);

clean:
    cleanMd5(&ctxt);

    return s;
}

int md5BufferC(
    uint8_t* buffer, 
    uint32_t buffer_ln, 
    unsigned char* hash_bytes, 
    uint16_t hash_bytes_size, 
    PMd5Ctxt ctxt
)
{
    return hashBufferC(buffer, buffer_ln, hash_bytes, hash_bytes_size, ctxt);
}

void hashToString(const unsigned char* hash, uint16_t hash_size, char* output, uint16_t output_size)
{
    uint16_t i = 0;

    for (i = 0; i < hash_size; i++)
    {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }

    output[output_size-1] = 0;
}

void printHash(const unsigned char* hash, uint16_t hash_size, const char* prefix, const char* postfix)
{
    uint16_t i = 0;

    printf("%s", prefix);
    for (i = 0; i < hash_size; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("%s", postfix);
}

int initSha1(PSha1Ctxt ctxt)
{
    return initHashCtxt(ctxt, BCRYPT_SHA1_ALGORITHM);
}

int initSha256(PSha256Ctxt ctxt)
{
    return initHashCtxt(ctxt, BCRYPT_SHA256_ALGORITHM);
}

int initMd5(PMd5Ctxt ctxt)
{
    return initHashCtxt(ctxt, BCRYPT_MD5_ALGORITHM);
}

int initHashCtxt(PHashCtxt ctxt, LPCWSTR AlgId)
{
    int s = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE heap = GetProcessHeap();

    memset(ctxt, 0, sizeof(HashCtxt));

    //open an algorithm handle
    status = BCryptOpenAlgorithmProvider(
        &(ctxt->alg),
        AlgId,
        NULL,
        0);
    if (!NT_SUCCESS(status))
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptOpenAlgorithmProvider\n", status);
#endif
        cleanHashCtxt(ctxt);
        return -1;
    }

    //calculate the size of the buffer to hold the hash object
    status = BCryptGetProperty(
        ctxt->alg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE) &(ctxt->hash_object_size),
        sizeof(DWORD),
        &(ctxt->data_size),
        0);
    if (!NT_SUCCESS(status))
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptGetProperty\n", status);
#endif
        cleanHashCtxt(ctxt);
        return -2;
    }

    // allocate the hash object on the heap
    ctxt->hash_object = (PBYTE)HeapAlloc(heap, 0, ctxt->hash_object_size);
    if ( NULL == ctxt->hash_object )
    {
#ifdef ERROR_PRINT
        printf("ERROR: memory allocation failed\n");
#endif
        cleanHashCtxt(ctxt);
        return -3;
    }

    // calculate the length of the hash
    status = BCryptGetProperty(
        ctxt->alg,
        BCRYPT_HASH_LENGTH,
        (PBYTE)&(ctxt->hash_size),
        sizeof(DWORD),
        &(ctxt->data_size),
        0);
    if (!NT_SUCCESS(status))
    {
#ifdef ERROR_PRINT
        printf("Error 0x%x returned by BCryptGetProperty\n", status);
#endif
        cleanHashCtxt(ctxt);
        return -4;
    }

    return s;
}

int createHash(PHashCtxt ctxt)
{
    if (ctxt->hash)
    {
        BCryptDestroyHash(ctxt->hash);
        ctxt->hash = NULL;
    }

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    status = BCryptCreateHash(
        ctxt->alg,
        &(ctxt->hash),
        ctxt->hash_object,
        ctxt->hash_object_size,
        NULL,
        0,
        0);
    if (!NT_SUCCESS(status))
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptCreateHash\n", status);
#endif
        cleanHashCtxt(ctxt);
        return 6;
    }
    return status;
}

int cleanSha1(PSha1Ctxt ctxt)
{
    return cleanHashCtxt(ctxt);
}

int cleanSha256(PSha256Ctxt ctxt)
{
    return cleanHashCtxt(ctxt);
}

int cleanMd5(PMd5Ctxt ctxt)
{
    return cleanHashCtxt(ctxt);
}

int cleanHashCtxt(PHashCtxt ctxt)
{
    HANDLE heap = GetProcessHeap();

    if (ctxt->alg)
    {
        BCryptCloseAlgorithmProvider(ctxt->alg, 0);
        ctxt->alg = NULL;
    }

    if (ctxt->hash)
    {
        BCryptDestroyHash(ctxt->hash);
        ctxt->hash = NULL;
    }

    if (ctxt->hash_object)
    {
        HeapFree(heap, 0, ctxt->hash_object);
        ctxt->hash_object = NULL;
    }

    return 0;
}
