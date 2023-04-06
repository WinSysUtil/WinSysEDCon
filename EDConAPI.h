#pragma once
#include "framework.h"

namespace EDCon_API {

	/**
	 * @brief 파일을 암호화하여 결과를 새로운 파일로 저장하는 함수
	 *
	 * @param pEncKey 암호화에 사용할 키
	 * @param pSrcPath 원본 파일 경로
	 * @param pDstPath 암호화된 결과를 저장할 파일 경로
	 * @return 성공 시 0, 실패 시 -1 반환
	 */
	WINSYSEDCON_API int EncryptToFile(const char* pEncKey, const char* pSrcPath, const char* pDstPath);


	/**
	 * @brief 파일을 복호화하여 결과를 새로운 파일로 저장하는 함수
	 *
	 * @param pDecKey 복호화에 사용할 키
	 * @param pSrcPath 암호화된 파일 경로
	 * @param pDstPath 복호화된 결과를 저장할 파일 경로
	 * @return 성공 시 0, 실패 시 -1 반환
	 */
	WINSYSEDCON_API int DecryptToFile(const char* pDecKey, const char* pSrcPath, const char* pDstPath);


	/**
	 * @brief 파일을 암호화하여 결과를 메모리에 저장하는 함수
	 *
	 * @param pEncKey 암호화에 사용할 키
	 * @param pSrcPath 원본 파일 경로
	 * @param pDst 암호화된 결과를 저장할 메모리 버퍼 포인터
	 * @param nLenDst 메모리 버퍼의 길이
	 * @return 성공 시 0, 실패 시 -1 반환
	 */
	WINSYSEDCON_API int EncryptToMemory(const char* pEncKey, const char* pSrcPath, void* pDst, int nLenDst, int * pnLenEnc);


	/**
	 * @brief 파일을 복호화하여 결과를 메모리에 저장하는 함수
	 *
	 * @param pDecKey 복호화에 사용할 키
	 * @param pSrcPath 암호화된 파일 경로
	 * @param pDst 복호화된 결과를 저장할 메모리 버퍼 포인터
	 * @param nLenDst 메모리 버퍼의 길이
	 * @return 성공 시 0, 실패 시 -1 반환
	 */
	WINSYSEDCON_API int DecryptToMemory(const char* pDecKey, const char* pSrcPath, void* pDst, int nLenDst, int * pnLenDec);

}