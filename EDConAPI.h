#pragma once
#include "framework.h"

namespace EDCon_API {

	/**
	 * @brief ������ ��ȣȭ�Ͽ� ����� ���ο� ���Ϸ� �����ϴ� �Լ�
	 *
	 * @param pEncKey ��ȣȭ�� ����� Ű
	 * @param pSrcPath ���� ���� ���
	 * @param pDstPath ��ȣȭ�� ����� ������ ���� ���
	 * @return ���� �� 0, ���� �� -1 ��ȯ
	 */
	WINSYSEDCON_API int EncryptToFile(const char* pEncKey, const char* pSrcPath, const char* pDstPath);


	/**
	 * @brief ������ ��ȣȭ�Ͽ� ����� ���ο� ���Ϸ� �����ϴ� �Լ�
	 *
	 * @param pDecKey ��ȣȭ�� ����� Ű
	 * @param pSrcPath ��ȣȭ�� ���� ���
	 * @param pDstPath ��ȣȭ�� ����� ������ ���� ���
	 * @return ���� �� 0, ���� �� -1 ��ȯ
	 */
	WINSYSEDCON_API int DecryptToFile(const char* pDecKey, const char* pSrcPath, const char* pDstPath);


	/**
	 * @brief ������ ��ȣȭ�Ͽ� ����� �޸𸮿� �����ϴ� �Լ�
	 *
	 * @param pEncKey ��ȣȭ�� ����� Ű
	 * @param pSrcPath ���� ���� ���
	 * @param pDst ��ȣȭ�� ����� ������ �޸� ���� ������
	 * @param nLenDst �޸� ������ ����
	 * @return ���� �� 0, ���� �� -1 ��ȯ
	 */
	WINSYSEDCON_API int EncryptToMemory(const char* pEncKey, const char* pSrcPath, void* pDst, int nLenDst, int * pnLenEnc);


	/**
	 * @brief ������ ��ȣȭ�Ͽ� ����� �޸𸮿� �����ϴ� �Լ�
	 *
	 * @param pDecKey ��ȣȭ�� ����� Ű
	 * @param pSrcPath ��ȣȭ�� ���� ���
	 * @param pDst ��ȣȭ�� ����� ������ �޸� ���� ������
	 * @param nLenDst �޸� ������ ����
	 * @return ���� �� 0, ���� �� -1 ��ȯ
	 */
	WINSYSEDCON_API int DecryptToMemory(const char* pDecKey, const char* pSrcPath, void* pDst, int nLenDst, int * pnLenDec);

}