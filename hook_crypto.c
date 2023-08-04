/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2015 Cuckoo Sandbox Developers, Optiv, Inc. (brad.spengler@optiv.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include "ntapi.h"
#include <wincrypt.h>
#include "hooking.h"
#include "log.h"
#include "CAPE\CAPE.h"

HOOKDEF(BOOL, WINAPI, CryptAcquireContextA,
	_Out_	  HCRYPTPROV *phProv,
	_In_	  LPCSTR pszContainer,
	_In_	  LPCSTR pszProvider,
	_In_	  DWORD dwProvType,
	_In_	  DWORD dwFlags
) {
	BOOL ret = Old_CryptAcquireContextA(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
	LOQ_bool("crypto", "ssh", "Container", pszContainer, "Provider", pszProvider, "Flags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptAcquireContextW,
	_Out_	  HCRYPTPROV *phProv,
	_In_	  LPCWSTR pszContainer,
	_In_	  LPCWSTR pszProvider,
	_In_	  DWORD dwProvType,
	_In_	  DWORD dwFlags
) {
	BOOL ret = Old_CryptAcquireContextW(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
	LOQ_bool("crypto", "uuh", "Container", pszContainer, "Provider", pszProvider, "Flags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptProtectData,
	_In_	  DATA_BLOB *pDataIn,
	_In_	  LPCWSTR szDataDescr,
	_In_	  DATA_BLOB *pOptionalEntropy,
	_In_	  PVOID pvReserved,
	_In_opt_  CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
	_In_	  DWORD dwFlags,
	_Out_	 DATA_BLOB *pDataOut
) {
	BOOL ret;
	ENSURE_STRUCT(pDataIn, DATA_BLOB);

	ret = 1;
	LOQ_bool("crypto", "b", "Buffer", pDataIn->cbData, pDataIn->pbData);
	return Old_CryptProtectData(pDataIn, szDataDescr, pOptionalEntropy,
		pvReserved, pPromptStruct, dwFlags, pDataOut);
}

HOOKDEF(BOOL, WINAPI, CryptUnprotectData,
	_In_		DATA_BLOB *pDataIn,
	_Out_opt_   LPWSTR *ppszDataDescr,
	_In_opt_	DATA_BLOB *pOptionalEntropy,
	_Reserved_  PVOID pvReserved,
	_In_opt_	CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
	_In_		DWORD dwFlags,
	_Out_	   DATA_BLOB *pDataOut
) {
	BOOL ret;
	DATA_BLOB _pOptionalEntropy;
	ENSURE_STRUCT(pDataOut, DATA_BLOB);
	memset(&_pOptionalEntropy, 0, sizeof(_pOptionalEntropy));
	if (pOptionalEntropy == NULL)
		pOptionalEntropy = &_pOptionalEntropy;

	ret = Old_CryptUnprotectData(pDataIn, ppszDataDescr,
		pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut);
	LOQ_bool("crypto", "bb", "Entropy", pOptionalEntropy->cbData, pOptionalEntropy->pbData,
		"Buffer", pDataOut->cbData, pDataOut->pbData);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptProtectMemory,
	_Inout_  LPVOID pData,
	_In_	 DWORD cbData,
	_In_	 DWORD dwFlags
) {
	BOOL ret = 1;
	LOQ_bool("crypto", "bi", "Buffer", cbData, pData, "Flags", dwFlags);
	ret = Old_CryptProtectMemory(pData, cbData, dwFlags);
	disable_tail_call_optimization();
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptUnprotectMemory,
	_Inout_  LPVOID pData,
	_In_	 DWORD cbData,
	_In_	 DWORD dwFlags
) {
	BOOL ret = Old_CryptUnprotectMemory(pData, cbData, dwFlags);
	LOQ_bool("crypto", "bi", "Buffer", cbData, pData, "Flags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptDecrypt,
	_In_	 HCRYPTKEY hKey,
	_In_	 HCRYPTHASH hHash,
	_In_	 BOOL Final,
	_In_	 DWORD dwFlags,
	_Inout_  BYTE *pbData,
	_Inout_  DWORD *pdwDataLen
) {
	BOOL ret = Old_CryptDecrypt(hKey, hHash, Final, dwFlags, pbData,
		pdwDataLen);
	if (ret && g_config.dump_crypto) {
		if (!CapeMetaData->DumpType)
			CapeMetaData->DumpType = DATADUMP;
		DumpMemoryRaw(pbData, *pdwDataLen);
		DebugOutput("CryptDecrypt hook: Dumped decrypted buffer at 0x%p (size 0x%x).\n", pbData, *pdwDataLen);
	}
	if (ret && g_config.unpacker && IsDisguisedPEHeader((PVOID)pbData)) {
		if (!CapeMetaData->DumpType)
			CapeMetaData->DumpType = UNPACKED_PE;
		CapeMetaData->Address = pbData;
		if (DumpImageInCurrentProcess((PVOID)pbData))
			DebugOutput("CryptDecrypt: Dumped decrypted PE image at 0x%p.\n", pbData);
	}
	LOQ_bool("crypto", "ppBii", "CryptKey", hKey, "CryptHash", hHash, "Buffer", pdwDataLen, pbData, "Length", *pdwDataLen, "Final", Final);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptEncrypt,
	_In_	 HCRYPTKEY hKey,
	_In_	 HCRYPTHASH hHash,
	_In_	 BOOL Final,
	_In_	 DWORD dwFlags,
	_Inout_  BYTE *pbData,
	_Inout_  DWORD *pdwDataLen,
	_In_	 DWORD dwBufLen
) {
	if (g_config.dump_crypto) {
		if (!CapeMetaData->DumpType)
			CapeMetaData->DumpType = DATADUMP;
		DumpMemoryRaw(pbData, *pdwDataLen);
		DebugOutput("CryptEncrypt hook: Dumped unencrypted buffer at 0x%p (size 0x%x).\n", pbData, *pdwDataLen);
	}
	BOOL ret = Old_CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
	LOQ_bool("crypto", "ppbii", "CryptKey", hKey, "CryptHash", hHash,
		"Buffer", dwBufLen, pbData, "Length", *pdwDataLen, "Final", Final);
	disable_tail_call_optimization();
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptHashData,
	_In_  HCRYPTHASH hHash,
	_In_  BYTE *pbData,
	_In_  DWORD dwDataLen,
	_In_  DWORD dwFlags
) {
	BOOL ret = Old_CryptHashData(hHash, pbData, dwDataLen, dwFlags);
	LOQ_bool("crypto", "pc", "CryptHash", hHash, "Buffer", dwDataLen, pbData);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptDecodeMessage,
	_In_		 DWORD dwMsgTypeFlags,
	_In_		 PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,
	_In_		 PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara,
	_In_		 DWORD dwSignerIndex,
	_In_		 const BYTE *pbEncodedBlob,
	_In_		 DWORD cbEncodedBlob,
	_In_		 DWORD dwPrevInnerContentType,
	_Out_opt_	DWORD *pdwMsgType,
	_Out_opt_	DWORD *pdwInnerContentType,
	_Out_opt_	BYTE *pbDecoded,
	_Inout_opt_  DWORD *pcbDecoded,
	_Out_opt_	PCCERT_CONTEXT *ppXchgCert,
	_Out_opt_	PCCERT_CONTEXT *ppSignerCert
) {
	BOOL ret = Old_CryptDecodeMessage(dwMsgTypeFlags, pDecryptPara,
		pVerifyPara, dwSignerIndex, pbEncodedBlob, cbEncodedBlob,
		dwPrevInnerContentType, pdwMsgType, pdwInnerContentType,
		pbDecoded, pcbDecoded, ppXchgCert, ppSignerCert);
	LOQ_bool("crypto", "B", "Buffer", pcbDecoded, pbDecoded);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptDecryptMessage,
	_In_		 PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,
	_In_		 const BYTE *pbEncryptedBlob,
	_In_		 DWORD cbEncryptedBlob,
	_Out_opt_	BYTE *pbDecrypted,
	_Inout_opt_  DWORD *pcbDecrypted,
	_Out_opt_	PCCERT_CONTEXT *ppXchgCert
) {
	BOOL ret = Old_CryptDecryptMessage(pDecryptPara, pbEncryptedBlob,
		cbEncryptedBlob, pbDecrypted, pcbDecrypted, ppXchgCert);
	LOQ_bool("crypto", "B", "Buffer", pcbDecrypted, pbDecrypted);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptEncryptMessage,
	_In_	 PCRYPT_ENCRYPT_MESSAGE_PARA pEncryptPara,
	_In_	 DWORD cRecipientCert,
	_In_	 PCCERT_CONTEXT rgpRecipientCert[],
	_In_	 const BYTE *pbToBeEncrypted,
	_In_	 DWORD cbToBeEncrypted,
	_Out_	BYTE *pbEncryptedBlob,
	_Inout_  DWORD *pcbEncryptedBlob
) {
	BOOL ret = 1;
	LOQ_bool("crypto", "b", "Buffer", cbToBeEncrypted, pbToBeEncrypted);
	ret = Old_CryptEncryptMessage(pEncryptPara, cRecipientCert,
		rgpRecipientCert, pbToBeEncrypted, cbToBeEncrypted, pbEncryptedBlob,
		pcbEncryptedBlob);
	disable_tail_call_optimization();
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptHashMessage,
	_In_		 PCRYPT_HASH_MESSAGE_PARA pHashPara,
	_In_		 BOOL fDetachedHash,
	_In_		 DWORD cToBeHashed,
	_In_		 const BYTE *rgpbToBeHashed[],
	_In_		 DWORD rgcbToBeHashed[],
	_Out_		BYTE *pbHashedBlob,
	_Inout_	  DWORD *pcbHashedBlob,
	_Out_opt_	BYTE *pbComputedHash,
	_Inout_opt_  DWORD *pcbComputedHash
) {
	DWORD length = 0;
	DWORD i;
	BOOL ret;
	uint8_t *mem;

	for (i = 0; i < cToBeHashed; i++) {
		length += rgcbToBeHashed[i];
	}

	mem = malloc(length);
	if(mem != NULL) {
		unsigned int off = 0;
		for (i = 0, off = 0; i < cToBeHashed; i++) {
			memcpy(mem + off, rgpbToBeHashed[i], rgcbToBeHashed[i]);
			off += rgcbToBeHashed[i];
		}
	}

	ret = Old_CryptHashMessage(pHashPara, fDetachedHash, cToBeHashed,
		rgpbToBeHashed, rgcbToBeHashed, pbHashedBlob, pcbHashedBlob,
		pbComputedHash, pcbComputedHash);
	LOQ_bool("crypto", "b", "Buffer", length, mem);

	if(mem != NULL) {
		free(mem);
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptDeriveKey,
	_In_   HCRYPTPROV hProv,
	_In_   ALG_ID Algid,
	_In_   HCRYPTHASH hBaseData,
	_In_   DWORD dwFlags,
	_Out_  HCRYPTKEY *phKey
) {
	BOOL ret = Old_CryptDeriveKey(hProv, Algid, hBaseData, dwFlags, phKey);
	LOQ_bool("crypto", "hpp", "Algid", Algid, "BaseData", hBaseData, "CryptKey", *phKey);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptExportKey,
	_In_	 HCRYPTKEY hKey,
	_In_	 HCRYPTKEY hExpKey,
	_In_	 DWORD dwBlobType,
	_In_	 DWORD dwFlags,
	_Out_	BYTE *pbData,
	_Inout_  DWORD *pdwDataLen
) {
	BOOL ret = Old_CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen);
	if (pbData && pdwDataLen)
		LOQ_bool("crypto", "pbihi", "CryptKey", hKey, "Buffer", *pdwDataLen, pbData, "BlobType", dwBlobType, "Flags", dwFlags, "Length", *pdwDataLen);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptDestroyKey,
	_In_   HCRYPTKEY hKey
) {
	BOOL ret = Old_CryptDestroyKey(hKey);
	LOQ_bool("crypto", "p", "CryptKey", hKey);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptGenKey,
	_In_   HCRYPTPROV hProv,
	_In_   ALG_ID Algid,
	_In_   DWORD dwFlags,
	_Out_  HCRYPTKEY *phKey
) {
	BOOL ret = Old_CryptGenKey(hProv, Algid, dwFlags, phKey);
	LOQ_bool("crypto", "h", "Algid", Algid);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptCreateHash,
	_In_   HCRYPTPROV hProv,
	_In_   ALG_ID Algid,
	_In_   HCRYPTKEY hKey,
	_In_   DWORD dwFlags,
	_Out_  HCRYPTHASH *phHash
) {
	BOOL ret = Old_CryptCreateHash(hProv, Algid, hKey, dwFlags, phHash);
	LOQ_bool("crypto", "hpp", "Algid", Algid, "CryptKey", hKey, "Hash object", *phHash);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptDestroyHash,
	_In_   HCRYPTHASH hHash
) {
	BOOL ret = Old_CryptDestroyHash(hHash);
	LOQ_bool("crypto", "p", "CryptHash", hHash);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, HTTPSCertificateTrust,
	PVOID data // PCRYPT_PROVIDER_DATA
) {
	BOOL ret = Old_HTTPSCertificateTrust(data);
	LOQ_hresult("crypto", "");
	return ret;
}

HOOKDEF(HRESULT, WINAPI, HTTPSFinalProv,
	PVOID data // PCRYPT_PROVIDER_DATA
) {
	BOOL ret = Old_HTTPSFinalProv(data);
	LOQ_hresult("crypto", "");
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptDecodeObjectEx,
	_In_		  DWORD			  dwCertEncodingType,
	_In_		  LPCSTR			 lpszStructType,
	_In_	const BYTE			   *pbEncoded,
	_In_		  DWORD			  cbEncoded,
	_In_		  DWORD			  dwFlags,
	_In_		  PCRYPT_DECODE_PARA pDecodePara,
	_Out_		 void			   *pvStructInfo,
	_Inout_	   DWORD			  *pcbStructInfo
) {
	BOOL ret = Old_CryptDecodeObjectEx(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pDecodePara, pvStructInfo, pcbStructInfo);
	LOQ_bool("crypto", "hbh", "CertEncodingType", dwCertEncodingType, "Encoded", cbEncoded, pbEncoded, "Flags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptImportPublicKeyInfo,
	_In_  HCRYPTPROV			hCryptProv,
	_In_  DWORD				 dwCertEncodingType,
	_In_  PCERT_PUBLIC_KEY_INFO pInfo,
	_Out_ HCRYPTKEY			 *phKey
) {
	BOOL ret = Old_CryptImportPublicKeyInfo(hCryptProv, dwCertEncodingType, pInfo, phKey);
	LOQ_bool("crypto", "hsb", "CertEncodingType", dwCertEncodingType, "AlgOID", pInfo->Algorithm.pszObjId, "Blob", pInfo->PublicKey.cbData, pInfo->PublicKey.pbData);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptEnumProvidersA,
	_In_	DWORD  dwIndex,
	_In_	DWORD  *pdwReserved,
	_In_	DWORD  dwFlags,
	_Out_   DWORD  *pdwProvType,
	_Out_   LPSTR pszProvName,
	_Inout_ DWORD  *pcbProvName
) {
	BOOL ret = Old_CryptEnumProvidersA(dwIndex, pdwReserved, dwFlags, pdwProvType, pszProvName, pcbProvName);
	LOQ_bool("crypto", "is", "Index", dwIndex, "ProviderName", pszProvName);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptEnumProvidersW,
	_In_	DWORD  dwIndex,
	_In_	DWORD  *pdwReserved,
	_In_	DWORD  dwFlags,
	_Out_   DWORD  *pdwProvType,
	_Out_   LPWSTR pszProvName,
	_Inout_ DWORD  *pcbProvName
) {
	BOOL ret = Old_CryptEnumProvidersW(dwIndex, pdwReserved, dwFlags, pdwProvType, pszProvName, pcbProvName);
	LOQ_bool("crypto", "iu", "Index", dwIndex, "ProviderName", pszProvName);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptHashSessionKey,
	_In_	 HCRYPTHASH hHash,
	_In_	 HCRYPTKEY hKey,
	_In_	 DWORD dwFlags
) {
	BOOL ret = Old_CryptHashSessionKey(hHash, hKey, dwFlags);
	LOQ_bool("crypto", "pph", "CryptHash", hHash, "CryptKey", hKey, "Flags", dwFlags);
	return ret;
}

HOOKDEF(DWORD, WINAPI, QueryUsersOnEncryptedFile,
  LPCWSTR   lpFileName,
  PVOID	 *pUsers
) {
	DWORD ret = Old_QueryUsersOnEncryptedFile(lpFileName, pUsers);
	LOQ_nonzero("crypto", "up", "FileName", lpFileName, "pUsers", pUsers);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptGenRandom,
	HCRYPTPROV hProv,
	DWORD	  dwLen,
	BYTE	   *pbBuffer
) {
	BOOL ret = Old_CryptGenRandom(hProv, dwLen, pbBuffer);
	LOQ_bool("crypto", "b", "Buffer", dwLen, pbBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptImportKey,
	HCRYPTPROV hProv,
	const BYTE *pbData,
	DWORD	  dwDataLen,
	HCRYPTKEY  hPubKey,
	DWORD	  dwFlags,
	HCRYPTKEY  *phKey
) {
	BOOL ret = Old_CryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);
	LOQ_bool("crypto", "bhpi", "KeyBlob", dwDataLen, pbData, "Flags", dwFlags,  "CryptKey", *phKey, "Length", dwDataLen);
	return ret;
}

HOOKDEF(SECURITY_STATUS, WINAPI, NCryptImportKey,
	NCRYPT_PROV_HANDLE hProvider,
	NCRYPT_KEY_HANDLE  hImportKey,
	LPCWSTR			pszBlobType,
	NCryptBufferDesc   *pParameterList,
	NCRYPT_KEY_HANDLE  *phKey,
	PBYTE			  pbData,
	DWORD			  cbData,
	DWORD			  dwFlags
) {
	BOOL ret = Old_NCryptImportKey(hProvider, hImportKey, pszBlobType, pParameterList, phKey, pbData, cbData, dwFlags);
	LOQ_bool("crypto", "bhp", "KeyBlob", cbData, pbData, "Flags", dwFlags,  "CryptKey", *phKey, "Length", cbData);
	return ret;
}

HOOKDEF(SECURITY_STATUS, WINAPI, NCryptDecrypt,
	NCRYPT_KEY_HANDLE hKey,
	PBYTE			 pbInput,
	DWORD			 cbInput,
	VOID			  *pPaddingInfo,
	PBYTE			 pbOutput,
	DWORD			 cbOutput,
	DWORD			 *pcbResult,
	DWORD			 dwFlags
) {
	BOOL ret = Old_NCryptDecrypt(hKey, pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags);
	if (ret && g_config.dump_crypto) {
		if (!CapeMetaData->DumpType)
			CapeMetaData->DumpType = DATADUMP;
		DumpMemoryRaw(pbInput, cbOutput);
		DebugOutput("NCryptDecrypt hook: Dumped decrypted buffer at 0x%p (size 0x%x).\n", pbInput, cbInput);
	}
	if (ret && g_config.unpacker && IsDisguisedPEHeader((PVOID)pbInput)) {
		if (!CapeMetaData->DumpType)
			CapeMetaData->DumpType = UNPACKED_PE;
		CapeMetaData->Address = pbInput;
		if (DumpImageInCurrentProcess((PVOID)pbInput))
			DebugOutput("NCryptDecrypt: Dumped decrypted PE image at 0x%p.\n", pbInput);
	}
	LOQ_bool("crypto", "bhpi", "Output", cbOutput, pbOutput, "Flags", dwFlags, "CryptKey", hKey, "Length", cbOutput);
	return ret;
}

HOOKDEF(SECURITY_STATUS, WINAPI, NCryptEncrypt,
	NCRYPT_KEY_HANDLE hKey,
	PBYTE			 pbInput,
	DWORD			 cbInput,
	VOID			  *pPaddingInfo,
	PBYTE			 pbOutput,
	DWORD			 cbOutput,
	DWORD			 *pcbResult,
	DWORD			 dwFlags
) {
	if (g_config.dump_crypto) {
		if (!CapeMetaData->DumpType)
			CapeMetaData->DumpType = DATADUMP;
		DumpMemoryRaw(pbInput, cbInput);
		DebugOutput("NCryptEncrypt hook: Dumped unencrypted buffer at 0x%p (size 0x%x).\n", pbInput, cbInput);
	}	
	BOOL ret = Old_NCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags);
	LOQ_bool("crypto", "bhpi", "Output", cbInput, pbInput, "Flags", dwFlags, "CryptKey", hKey, "Length", cbInput);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, BCryptImportKey,
	BCRYPT_ALG_HANDLE	hAlgorithm,
	BCRYPT_KEY_HANDLE	hImportKey,
	LPCWSTR				pszBlobType,
	BCRYPT_KEY_HANDLE	*phKey,
	PUCHAR				pbKeyObject,
	ULONG				cbKeyObject,
	PUCHAR				pbInput,
	ULONG				cbInput,
	ULONG				dwFlags
) {
	NTSTATUS ret = Old_BCryptImportKey(hAlgorithm, hImportKey, pszBlobType, phKey, pbKeyObject, cbKeyObject, pbInput, cbInput, dwFlags);
	LOQ_ntstatus("crypto", "bhpi", "KeyBlob", cbInput, pbInput, "Flags", dwFlags, "CryptKey", *phKey, "Length", cbInput);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, BCryptImportKeyPair,
	BCRYPT_ALG_HANDLE	hAlgorithm,
	BCRYPT_KEY_HANDLE	hImportKey,
	LPCWSTR				pszBlobType,
	BCRYPT_KEY_HANDLE   * phKey,
	PUCHAR				pbInput,
	ULONG				cbInput,
	ULONG				dwFlags
) {
	if (g_config.dump_keys) {
		if (!CapeMetaData->DumpType)
			CapeMetaData->DumpType = DATADUMP;
		DumpMemoryRaw(pbInput, cbInput);
		DebugOutput("BCryptImportKeyPair hook: Dumped ImportKey buffer at 0x%p (size 0x%x).\n", pbInput, cbInput);
	}
	NTSTATUS ret = Old_BCryptImportKeyPair(hAlgorithm, hImportKey, pszBlobType, phKey, pbInput, cbInput, dwFlags);
	LOQ_ntstatus("crypto", "bhpi", "KeyBlob", cbInput, pbInput, "Flags", dwFlags, "CryptKey", *phKey, "Length", cbInput);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, BCryptDecrypt,
	BCRYPT_KEY_HANDLE	hKey,
	PUCHAR				pbInput,
	ULONG				cbInput,
	VOID				*pPaddingInfo,
	PUCHAR				pbIV,
	ULONG				cbIV,
	PUCHAR				pbOutput,
	ULONG				cbOutput,
	ULONG				*pcbResult,
	ULONG				dwFlags
) {
	NTSTATUS ret = Old_BCryptDecrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
	if (ret && g_config.dump_crypto) {
		if (!CapeMetaData->DumpType)
			CapeMetaData->DumpType = DATADUMP;
		DumpMemoryRaw(pbInput, cbOutput);
		DebugOutput("BCryptDecrypt hook: Dumped decrypted buffer at 0x%p (size 0x%x).\n", pbInput, cbInput);
	}
	if (ret && g_config.unpacker && IsDisguisedPEHeader((PVOID)pbInput)) {
		if (!CapeMetaData->DumpType)
			CapeMetaData->DumpType = UNPACKED_PE;
		CapeMetaData->Address = pbInput;
		if (DumpImageInCurrentProcess((PVOID)pbInput))
			DebugOutput("BCryptDecrypt: Dumped decrypted PE image at 0x%p.\n", pbInput);
	}
	LOQ_ntstatus("crypto", "bbhpi", "Output", cbOutput, pbOutput, "IV", cbIV, pbIV, "Flags", dwFlags, "CryptKey", hKey, "Length", cbOutput);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, BCryptEncrypt,
	BCRYPT_KEY_HANDLE	hKey,
	PUCHAR				pbInput,
	ULONG				cbInput,
	VOID				*pPaddingInfo,
	PUCHAR				pbIV,
	ULONG				cbIV,
	PUCHAR				pbOutput,
	ULONG				cbOutput,
	ULONG				*pcbResult,
	ULONG				dwFlags
) {
	if (g_config.dump_crypto) {
		if (!CapeMetaData->DumpType)
			CapeMetaData->DumpType = DATADUMP;
		DumpMemoryRaw(pbInput, cbInput);
		DebugOutput("BCryptEncrypt hook: Dumped unencrypted buffer at 0x%p (size 0x%x).\n", pbInput, cbInput);
	}
	NTSTATUS ret = Old_BCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
	LOQ_ntstatus("crypto", "bbhpi", "Input", cbInput, pbInput, "IV", cbIV, pbIV, "Flags", dwFlags, "CryptKey", hKey, "Length", cbInput);
	return ret;
}
