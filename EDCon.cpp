#include "pch.h"
#include "EDConAPI.h"



#ifdef min
#undef min
#endif

constexpr size_t BUFFER_SIZE = 1024 * 1024;
WINSYSEDCON_API int EDCon_API::EncryptToFile(const char* pEncKey, const char* pSrcPath, const char* pDstPath) {
    ByteArray key, enc;
    size_t file_len;

    FILE* input, * output;

    srand(time(0));

    size_t key_len = 0;
    while (pEncKey[key_len] != 0)
        key.push_back(pEncKey[key_len++]);

    input = fopen(pSrcPath, "rb");
    if (input == 0) {
        fprintf(stderr, "Cannot read file '%s'\n", pSrcPath);
        return 1;
    }

    output = fopen(pDstPath, "wb");
    if (output == 0) {
        fprintf(stderr, "Cannot write file '%s'\n", pDstPath);
        return 1;
    }

    Aes256 aes(key);

    fseek(input, 0, SEEK_END);
    file_len = ftell(input);
    fseek(input, 0, SEEK_SET);
    printf("File is %zd bytes\n", file_len);

    enc.clear();
    aes.encrypt_start(file_len, enc);
    fwrite(enc.data(), enc.size(), 1, output);

    while (!feof(input)) {
        unsigned char* buffer = new unsigned char[BUFFER_SIZE];
        size_t buffer_len;

        buffer_len = fread(buffer, 1, BUFFER_SIZE, input);
        printf("Read %zd bytes\n", buffer_len);
        if (buffer_len > 0) {
            enc.clear();
            aes.encrypt_continue(buffer, buffer_len, enc);
            fwrite(enc.data(), enc.size(), 1, output);
        }
        delete[] buffer;
    }

    enc.clear();
    aes.encrypt_end(enc);
    fwrite(enc.data(), enc.size(), 1, output);

    fclose(input);
    fclose(output);

    return 0;
}

WINSYSEDCON_API int EDCon_API::DecryptToFile(const char* pDecKey, const char* pSrcPath, const char* pDstPath) {
    ByteArray key, dec;
    size_t file_len;

    FILE* input, * output;

    srand(time(0));

    size_t key_len = 0;
    while (pDecKey[key_len] != 0)
        key.push_back(pDecKey[key_len++]);

    input = fopen(pSrcPath, "rb");
    if (input == 0) {
        fprintf(stderr, "Cannot read file '%s'\n", pSrcPath);
        return 1;
    }

    output = fopen(pDstPath, "wb");
    if (output == 0) {
        fprintf(stderr, "Cannot write file '%s'\n", pDstPath);
        return 1;
    }

    Aes256 aes(key);

    fseek(input, 0, SEEK_END);
    file_len = ftell(input);
    fseek(input, 0, SEEK_SET);
    printf("File is %zd bytes\n", file_len);

    aes.decrypt_start(file_len);

    while (!feof(input)) {
        unsigned char* buffer = new unsigned char[BUFFER_SIZE];
        size_t buffer_len;

        buffer_len = fread(buffer, 1, BUFFER_SIZE, input);
        printf("Read %zd bytes\n", buffer_len);
        if (buffer_len > 0) {
            dec.clear();
            aes.decrypt_continue(buffer, buffer_len, dec);
            fwrite(dec.data(), dec.size(), 1, output);
        }
        delete[] buffer;
    }

    dec.clear();
    aes.decrypt_end(dec);
    fwrite(dec.data(), dec.size(), 1, output);

    fclose(input);
    fclose(output);

    return 0;
}

WINSYSEDCON_API int EDCon_API::EncryptToMemory(const char* pEncKey, const char* pSrcPath, void* pDst, int nLenDst, int* pnLenEnc) {
    ByteArray key, enc;
    size_t file_len;

    FILE* input;

    srand(time(0));

    size_t key_len = 0;
    while (pEncKey[key_len] != 0)
        key.push_back(pEncKey[key_len++]);

    input = fopen(pSrcPath, "rb");
    if (input == 0) {
        fprintf(stderr, "Cannot read file '%s'\n", pSrcPath);
        return 1;
    }

    Aes256 aes(key);

    fseek(input, 0, SEEK_END);
    file_len = ftell(input);
    fseek(input, 0, SEEK_SET);
    printf("File is %zd bytes\n", file_len);

    enc.clear();
    aes.encrypt_start(file_len, enc);

    if (enc.size() > nLenDst) {
        fprintf(stderr, "Buffer too small\n");
        return 1;
    }

    memcpy(pDst, enc.data(), enc.size());
    *pnLenEnc = enc.size();
    unsigned char* pDstCur = (unsigned char*)pDst + enc.size();

    while (!feof(input)) {
        unsigned char* buffer = new unsigned char[BUFFER_SIZE];
        size_t buffer_len;

        buffer_len = fread(buffer, 1, BUFFER_SIZE, input);
        printf("Read %zd bytes\n", buffer_len);
        if (buffer_len > 0) {
            enc.clear();
            aes.encrypt_continue(buffer, buffer_len, enc);

            if (pDstCur + enc.size() - (unsigned char*)pDst > nLenDst) {
                fprintf(stderr, "Buffer too small\n");
                return 1;
            }

            memcpy(pDstCur, enc.data(), enc.size());
            pDstCur += enc.size();
        }
        delete[] buffer;
    }

    enc.clear();
    aes.encrypt_end(enc);

    if (pDstCur + enc.size() - (unsigned char*)pDst > nLenDst) {
        fprintf(stderr, "Buffer too small\n");
        return 1;
    }

    memcpy(pDstCur, enc.data(), enc.size());
    *pnLenEnc += enc.size();

    fclose(input);

    return 0;
}

WINSYSEDCON_API int EDCon_API::DecryptToMemory(const char* pDecKey, const char* pSrcPath, void* pDst, int nLenDst, int* pnLenDec) {
    ByteArray key, dec;
    size_t file_len;

    FILE* input;

    srand(time(0));

    size_t key_len = 0;
    while (pDecKey[key_len] != 0)
        key.push_back(pDecKey[key_len++]);

    input = fopen(pSrcPath, "rb");
    if (input == 0) {
        fprintf(stderr, "Cannot read file '%s'\n", pSrcPath);
        return 1;
    }

    Aes256 aes(key);

    fseek(input, 0, SEEK_END);
    file_len = ftell(input);
    fseek(input, 0, SEEK_SET);
    printf("File is %zd bytes\n", file_len);

    aes.decrypt_start(file_len);

    unsigned char* pDstCur = (unsigned char*)pDst;

    while (!feof(input)) {
        unsigned char* buffer = new unsigned char[BUFFER_SIZE];
        size_t buffer_len;

        buffer_len = fread(buffer, 1, BUFFER_SIZE, input);
        printf("Read %zd bytes\n", buffer_len);
        if (buffer_len > 0) {
            dec.clear();
            aes.decrypt_continue(buffer, buffer_len, dec);

            if (pDstCur + dec.size() - (unsigned char*)pDst > nLenDst) {
                fprintf(stderr, "Buffer too small\n");
                return 1;
            }

            memcpy(pDstCur, dec.data(), dec.size());
            pDstCur += dec.size();
        }
        delete[] buffer;
    }

    dec.clear();
    aes.decrypt_end(dec);

    if (pDstCur + dec.size() - (unsigned char*)pDst > nLenDst) {
        fprintf(stderr, "Buffer too small\n");
        return 1;
    }

    memcpy(pDstCur, dec.data(), dec.size());
    *pnLenDec = pDstCur + dec.size() - (unsigned char*)pDst;

    fclose(input);

    return 0;
}
