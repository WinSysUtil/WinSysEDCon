#pragma once

#include <functional>
#include <utility>
#include <utility>

#define BUFFER_SIZE 1024 * 1024
#define MAX_BUFFER_SIZE 1024 * 1024

#ifdef min
#undef min
#endif

class CEDConMngr {
public:
    int EncryptToFile(const char* pEncKey, const char* pSrcPath, const char* pDstPath) {
        ByteArray enc;
        int enc_len = 0;

        if (EncryptToMemory(pEncKey, pSrcPath, &enc, MAX_BUFFER_SIZE, &enc_len) != 0) {
            fprintf(stderr, "Cannot encrypt file '%s'\\\\\\\\n", pSrcPath);
            return 1;
        }

        FILE* output = fopen(pDstPath, "wb");
        if (output == 0) {
            fprintf(stderr, "Cannot write file '%s'\\\\\\\\n", pDstPath);
            return 1;
        }

        fwrite(enc.data(), enc_len, 1, output);

        fclose(output);

        return 0;
    }

    int DecryptToFile(const char* pDecKey, const char* pSrcPath, const char* pDstPath) {
        ByteArray dec;
        int dec_len = 0;

        FILE* input = fopen(pSrcPath, "rb");
        if (input == 0) {
            fprintf(stderr, "Cannot read file '%s'\\\\\\\\n", pSrcPath);
            return 1;
        }

        fseek(input, 0, SEEK_END);
        size_t file_len = ftell(input);
        fseek(input, 0, SEEK_SET);

        if (file_len > MAX_BUFFER_SIZE) {
            fprintf(stderr, "File too large\\\\\\\\n");
            return 1;
        }

        dec.resize(file_len);

        fread(dec.data(), file_len, 1, input);
        fclose(input);

        if (DecryptToMemory(pDecKey, dec.data(), dec.size(), &dec_len) != 0) {
            fprintf(stderr, "Cannot decrypt file '%s'\\\\\\\\n", pSrcPath);
            return 1;
        }

        FILE* output = fopen(pDstPath, "wb");
        if (output == 0) {
            fprintf(stderr, "Cannot write file '%s'\\\\\\\\n", pDstPath);
            return 1;
        }

        fwrite(dec.data(), dec_len, 1, output);

        fclose(output);

        return 0;
    }

    int EncryptToMemory(const char* pEncKey, const char* pSrcPath, void* pDst, int nLenDst, int* pnLenEnc) {
        ByteArray key, enc;
        size_t file_len;

        FILE* input;

        srand(time(0));

        size_t key_len = 0;
        while (pEncKey[key_len] != 0)
            key.push_back(pEncKey[key_len++]);

        input = fopen(pSrcPath, "rb");
        if (input == 0) {
            fprintf(stderr, "Cannot read file '%s'\\\\\\\\n", pSrcPath);
            return 1;
        }

        Aes256 aes(key);

        fseek(input, 0, SEEK_END);
        file_len = ftell(input);
        fseek(input, 0, SEEK_SET);
        printf("File is %zd bytes\\\\\\\\n", file_len);

        enc.clear();
        aes.encrypt_start(file_len, enc);

        if (enc.size() > nLenDst) {
            fprintf(stderr, "Buffer too small\\\\\\\\n");
            return 1;
        }

        memcpy(pDst, enc.data(), enc.size());
        *pnLenEnc = enc.size();
        unsigned char* pDstCur = (unsigned char*)pDst + enc.size();

        while (!feof(input)) {
            unsigned char* buffer = new unsigned char[BUFFER_SIZE];
            size_t buffer_len;

            buffer_len = fread(buffer, 1, BUFFER_SIZE, input);
            printf("Read %zd bytes\\\\\\\\n", buffer_len);
            if (buffer_len > 0) {
                enc.clear();
                aes.encrypt_continue(buffer, buffer_len, enc);

                if (pDstCur + enc.size() - (unsigned char*)pDst > nLenDst) {
                    fprintf(stderr, "Buffer too small\\\\\\\\n");
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
            fprintf(stderr, "Buffer too small\\\\\\\\n");
            return 1;
        }

        memcpy(pDstCur, enc.data(), enc.size());
        *pnLenEnc += enc.size();

        fclose(input);

        return 0;
    }

    int DecryptToMemory(const char* pDecKey, const void* pSrc, int nLenSrc, int* pnLenDec) {
        ByteArray key, dec;

        srand(time(0));

        size_t key_len = 0;
        while (pDecKey[key_len] != 0)
            key.push_back(pDecKey[key_len++]);

        Aes256 aes(key);

        if (nLenSrc > MAX_BUFFER_SIZE) {
            fprintf(stderr, "Buffer too small\\\\\\\\n");
            return 1;
        }

        dec.resize(MAX_BUFFER_SIZE);

        aes.decrypt_start(nLenSrc);

        const unsigned char* pSrcCur = (const unsigned char*)pSrc;

        while (pSrcCur < (const unsigned char*)pSrc + nLenSrc) {
            size_t buffer_len = 0;
            aes.decrypt_continue(pSrcCur, std::min(static_cast<ByteArray::size_type>((const unsigned char*)pSrc + nLenSrc - pSrcCur), static_cast<ByteArray::size_type>(BUFFER_SIZE)), dec);
            pSrcCur += buffer_len;
        }

        aes.decrypt_end(dec);

        *pnLenDec = dec.size();

        return 0;
    }
};
