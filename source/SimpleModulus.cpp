// ----------------------------------------------------------------------------------------------------------
// Copyright (c) 2014 Guido Pola <prodito(at)live.com>
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
// ----------------------------------------------------------------------------------------------------------
#include <windows.h>
#include "SimpleModulus.h"

//
// MSVC 6.0 for scope hack.
//
#if _MSC_VER == 1200
#define for if(1) for
#endif // _MSC_VER == 1200



//
//
// 
#pragma pack(1)
struct KEYFILE_FILEHEADER {
	WORD	type;
	DWORD	size;
};
#pragma pack()

//
//
// 
#define KEYFILE_ALLKEY	0x1111
#define KEYFILE_ONEKEY	0x1112

//
//
// 
#define CALCULATE_KEYFILE_SIZE(x) (((x) * (sizeof(DWORD) * ENCRYPTION_KEY_SIZE)) + sizeof(KEYFILE_FILEHEADER))

//
//
// 
DWORD CSimpleModulus::s_dwSaveLoadXOR[ENCRYPTION_KEY_SIZE] = {0x3F08A79B, 0xE25CC287, 0x93D27AB9, 0x20DEA7BF};

CSimpleModulus::CSimpleModulus()
{ 
	Init();
}


CSimpleModulus::~CSimpleModulus()
{

}

void CSimpleModulus::Init()
{
	memset(m_dwEncryptionKey, 0, sizeof(m_dwEncryptionKey));
	memset(m_dwModulus, 0, sizeof(m_dwModulus));
	memset(m_dwDecryptionKey, 0, sizeof(m_dwDecryptionKey));
} 

int CSimpleModulus::Encrypt(void* lpDest, void* lpSource, int iSize)
{
	//
	//
	// 
	int iTotalSize = ((iSize + ENCRYPTION_BLOCK_SIZE - 1) / ENCRYPTION_BLOCK_SIZE) * ENCRYPTED_BLOCK_SIZE;

	//
	if( lpDest == NULL )
	{
		return iTotalSize;
	}

	PBYTE pbySource = (LPBYTE)lpSource;
	PBYTE pbyTarget = (LPBYTE)lpDest;

	//
	//
	// 
	for( int i = 0; i < iSize; i+= ENCRYPTION_BLOCK_SIZE, pbySource += ENCRYPTION_BLOCK_SIZE, pbyTarget += ENCRYPTED_BLOCK_SIZE )
	{
		int k;
		if( ( iSize - i ) < ENCRYPTION_BLOCK_SIZE )
			k = iSize - i;
		else
			k = ENCRYPTION_BLOCK_SIZE;

		//
		//
		// 
		EncryptBlock(pbyTarget, pbySource, k);
	}
	return iTotalSize;
}

//
//
//
int CSimpleModulus::Decrypt(void* lpDest, void* lpSource, int iSize)
{
	//
	//
	//
	if( lpDest == NULL )
	{
		return ((iSize + ENCRYPTED_BLOCK_SIZE - 1 ) / ENCRYPTED_BLOCK_SIZE) * ENCRYPTION_BLOCK_SIZE;
	}

	//
	int iTotalSize	= 0;
	PBYTE pbyTarget = (LPBYTE)lpDest;
	PBYTE pbySource = (LPBYTE)lpSource;

	//
	//
	//
	for( int i = 0; i < iSize; i += ENCRYPTED_BLOCK_SIZE, pbySource += ENCRYPTED_BLOCK_SIZE, pbyTarget += ENCRYPTION_BLOCK_SIZE  )
	{
		//
		//
		// 
		int iBlockSize = DecryptBlock(pbyTarget, pbySource);

		//
		//
		//
		if( iBlockSize < 0 )
		{
			return iBlockSize;
		}

		//
		//
		// 
		iTotalSize += iBlockSize;
	}
	return iTotalSize;
}


//
//
//
void CSimpleModulus::EncryptBlock(void* lpTarget, void* lpSource, int nSize)
{
	DWORD dwEncBuffer[ ENCRYPTION_KEY_SIZE ];
	memset(lpTarget, 0, ENCRYPTED_BLOCK_SIZE);

	LPBYTE lpSrcPtr = (LPBYTE)lpSource;
	DWORD dwPrev = 0;

	for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++, lpSrcPtr += 2 )
	{
		DWORD dwNext = 0;

		memcpy(&dwNext, lpSrcPtr, 2);

		dwEncBuffer[ i ] = ((dwNext ^ m_dwXORKey[ i ] ^ dwPrev) * m_dwEncryptionKey[ i ]) % m_dwModulus[ i ];
		dwPrev			 = dwEncBuffer[ i ] & 0xFFFF;
	}

	dwPrev = dwEncBuffer[ ENCRYPTION_KEY_SIZE - 1 ] & 0xFFFF;

	//
	for( int i = 2; i >= 0; i-- )
	{
		DWORD dwSrc = dwEncBuffer[ i ] & 0xFFFF;

		dwEncBuffer[ i ] = dwEncBuffer[ i ] ^ m_dwXORKey[ i ] ^ dwPrev;
		dwPrev			 = dwSrc;
	}

	int nTotalBits = 0;

	for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++ )
	{
		nTotalBits = AddBits(lpTarget, nTotalBits, &dwEncBuffer[ i ], 0, 16);
		nTotalBits = AddBits(lpTarget, nTotalBits, &dwEncBuffer[ i ], 22, 2);
	}

	BYTE cCheckSum[2]; 
	cCheckSum[0] = (nSize & 0xFF) ^ 0x3D;
	cCheckSum[1] = 0xF8;
	
	LPBYTE lpSourceSeek = (LPBYTE)lpSource;
	for( int i = 0; i < ENCRYPTION_BLOCK_SIZE; i++ )
	{
		cCheckSum[1] ^= lpSourceSeek[ i ];
	}

	cCheckSum[ 0 ] ^= cCheckSum[1];
	
	//
	nTotalBits = AddBits(lpTarget, nTotalBits, &cCheckSum, 0, 16);
}

//
//
//
int CSimpleModulus::DecryptBlock(void* lpTarget, void* lpSource)
{
	LPBYTE lpEncrypted = (LPBYTE)lpSource;
	DWORD dwDecBuffer[ENCRYPTION_KEY_SIZE];

	memset(lpTarget, 0, ENCRYPTION_BLOCK_SIZE);
	LPBYTE lpTgtPtr = (LPBYTE)lpTarget;

	memset(dwDecBuffer, 0, sizeof(dwDecBuffer));

	int nTotalBits = 0;

	for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++ )
	{
		AddBits(&dwDecBuffer[ i ], 0, lpEncrypted, nTotalBits, 16);
		nTotalBits += 16;
		
		AddBits(&dwDecBuffer[ i ], 22, lpEncrypted, nTotalBits, 2);
		nTotalBits += 2;
	}

	DWORD dwPrev = dwDecBuffer[ ENCRYPTION_KEY_SIZE - 1 ] & 0xFFFF;

	for( int i = 2; i >= 0; i-- )
	{
		dwDecBuffer[ i ] ^= m_dwXORKey[ i ];
		dwDecBuffer[ i ] ^= dwPrev;
		dwPrev			 = dwDecBuffer[ i ] & 0xFFFF;
	}

	dwPrev = 0;
	for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++, lpTgtPtr += 2 )
	{
		DWORD dwResult = (dwDecBuffer[i] * m_dwDecryptionKey[i]) % m_dwModulus[i] ^ m_dwXORKey[ i ] ^ dwPrev;

		memcpy(lpTgtPtr, &dwResult, 2);

		//
		dwPrev = dwDecBuffer[i] & 0xFFFF;
	}

	BYTE cCheckSum[2] = { 0 };
	
	
	AddBits(&cCheckSum, 0, lpEncrypted, nTotalBits, 16/*sizeof(dwDecBuffer)*/);
	nTotalBits += 16;
	
	cCheckSum[ 0 ] = cCheckSum[1] ^ (cCheckSum[0] ^ 0x3D);


	LPBYTE lpTgtSeek = (LPBYTE)lpTarget;
	BYTE cTempCheckSum = 0xF8;

	for( int i = 0; i < ENCRYPTION_BLOCK_SIZE; i++ )
		cTempCheckSum ^= lpTgtSeek[ i ];

	if( cCheckSum[1] != cTempCheckSum )
		return -1;

	return cCheckSum[0];
}

//
//
//
int CSimpleModulus::AddBits(void* lpBuffer, int nNumBufferBits, void* lpBits, int nInitialBit, int nNumBits)
{
	//
	//
	//
	int nBufferSize = (GetByteOfBit((nNumBits + nInitialBit) - 1) - GetByteOfBit(nInitialBit)) + 1;

	// Copy the Source Buffer
	LPBYTE lpTemp = new BYTE[ nBufferSize + 1 ];
	memset(lpTemp, 0, nBufferSize + 1);
	memcpy(lpTemp, (LPBYTE)lpBits + GetByteOfBit(nInitialBit), nBufferSize);

	//
	int nLastBitMod8 = (nNumBits + nInitialBit) % ENCRYPTION_BLOCK_SIZE;

	//
	//
	// 
	if( nLastBitMod8 != 0 )
	{
		lpTemp[nBufferSize - 1] &= (nLastBitMod8 | 0xFF) << (ENCRYPTION_BLOCK_SIZE - nLastBitMod8);
	}

	//
	// Get the Values to Shift
	// 
	int nShiftLeft	= (nInitialBit % ENCRYPTION_BLOCK_SIZE);
	int nShiftRight = (nNumBufferBits % ENCRYPTION_BLOCK_SIZE);
	
	//
	// Shift the Values to Add the right space of the desired bits
	//
	Shift(lpTemp, nBufferSize, -nShiftLeft);
	Shift(lpTemp, nBufferSize+1, nShiftRight);
	
	//
	// Copy the the bits of Source to the Dest
	// 
	int nMax = (( nShiftRight <= nShiftLeft ) ? 0 : 1) + nBufferSize;
	LPBYTE lpTarget = (LPBYTE)lpBuffer + GetByteOfBit(nNumBufferBits);
	LPBYTE lpSeek = lpTemp;

	for( int i = 0; i < nMax; i++, lpTarget++, lpSeek++ )
	{
		*lpTarget |= *lpSeek;
	}

	// Delete the temp Buffer
	delete[] lpTemp;

	// Return the number of bits of the new Dest Buffer
	return nNumBufferBits + nNumBits;
}


//
//
//
void CSimpleModulus::Shift(void* lpBuffer, int nByte, int nShift)
{
	//
	// The nShift can't be zero.
	//
	if( nShift == 0 )
	{
		return;
	}

	//
	if( nShift > 0 )
	{
		LPBYTE lpTemp = (LPBYTE)lpBuffer + (nByte - 1);
		for( int i = nByte - 1; i > 0 ; i--, lpTemp-- )
		{
			*lpTemp = ( *(lpTemp - 1) << (ENCRYPTION_BLOCK_SIZE - nShift)) | ( *lpTemp >> nShift );
		}

		//
		*lpTemp = *lpTemp >> nShift;
	}
	else
	{
		int nRealShift = -nShift;
		LPBYTE lpTemp = (LPBYTE)lpBuffer;

		for( int i = 0; i < nByte - 1; i++, lpTemp++ )
		{
			*lpTemp = ( *(lpTemp + 1) >> (ENCRYPTION_BLOCK_SIZE - nRealShift)) | ( *lpTemp << nRealShift );
		}

		//
		*lpTemp = *lpTemp << nRealShift;
	}
}


int CSimpleModulus::GetByteOfBit(int nBit)
{
	return nBit >> 3;
}

BOOL CSimpleModulus::SaveAllKey(LPSTR lpszFileName )
{
	return SaveKey(lpszFileName, KEYFILE_ALLKEY, TRUE, TRUE, TRUE, TRUE);
}

BOOL CSimpleModulus::LoadAllKey(char* lpszFileName)
{
	return LoadKey(lpszFileName, KEYFILE_ALLKEY, TRUE, TRUE, TRUE, TRUE);
}

BOOL CSimpleModulus::SaveEncryptionKey(char* lpszFileName)
{
	return SaveKey(lpszFileName, KEYFILE_ONEKEY, TRUE, TRUE, FALSE, TRUE);
}


BOOL CSimpleModulus::LoadEncryptionKey(char* lpszFileName)
{
	return LoadKey(lpszFileName, KEYFILE_ONEKEY, TRUE, TRUE, FALSE, TRUE);
}

BOOL CSimpleModulus::SaveDecryptionKey(char* lpszFileName)
{
	return SaveKey(lpszFileName, KEYFILE_ONEKEY, TRUE, FALSE, TRUE, TRUE);
}


BOOL CSimpleModulus::LoadDecryptionKey(char* lpszFileName)
{
	return LoadKey(lpszFileName, KEYFILE_ONEKEY, TRUE, FALSE, TRUE, TRUE);
}

//
//
//
BOOL CSimpleModulus::SaveKey(char* lpszFileName, WORD wFileHeader, BOOL bSaveModulus, BOOL bSaveEncKey, BOOL bSaveDecKey, BOOL bSaveXORKey)
{
	KEYFILE_FILEHEADER Chunk;
	DWORD dwBuffer[ ENCRYPTION_KEY_SIZE ];
	DWORD dwNumber;

	HANDLE hFile = CreateFile(lpszFileName, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if( hFile == INVALID_HANDLE_VALUE )
	{
		return FALSE;
	}

	Chunk.type = wFileHeader;
	Chunk.size = CALCULATE_KEYFILE_SIZE( bSaveModulus + bSaveEncKey + bSaveDecKey + bSaveXORKey );

	WriteFile(hFile, &Chunk, sizeof(KEYFILE_FILEHEADER), &dwNumber, NULL);

	if( bSaveModulus != FALSE )
	{
		for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++ )
		{
			dwBuffer[i] = m_dwModulus[i] ^ s_dwSaveLoadXOR[i];
		}
		WriteFile(hFile, &dwBuffer, sizeof(dwBuffer), &dwNumber, NULL);
	}

	if( bSaveEncKey != FALSE )
	{
		for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++ )
		{
			dwBuffer[i] = m_dwEncryptionKey[i] ^ s_dwSaveLoadXOR[i];
		}
		WriteFile(hFile, &dwBuffer, sizeof(dwBuffer), &dwNumber, NULL);
	}

	if( bSaveDecKey != FALSE )
	{
		for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++ )
		{
			dwBuffer[i] = m_dwDecryptionKey[i] ^ s_dwSaveLoadXOR[i];
		}
		WriteFile(hFile, &dwBuffer, sizeof(dwBuffer), &dwNumber, NULL);
	}

	if( bSaveXORKey != FALSE )
	{
		for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++ )
		{
			dwBuffer[i] = m_dwXORKey[i] ^ s_dwSaveLoadXOR[i];
		}
		WriteFile(hFile, &dwBuffer, sizeof(dwBuffer), &dwNumber, NULL);
	}

	CloseHandle(hFile);

	return TRUE;
}


//
//
//
BOOL CSimpleModulus::LoadKey(char* lpszFileName, WORD wFileHeader, BOOL bLoadModulus, BOOL bLoadEncKey, BOOL bLoadDecKey, BOOL bLoadXORKey)
{
	KEYFILE_FILEHEADER Chunk;
	DWORD dwNumber;
	DWORD dwBuffer[ENCRYPTION_KEY_SIZE];
	HANDLE hFile = CreateFile(lpszFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if ( hFile == INVALID_HANDLE_VALUE )
	{
		return FALSE;
	}

	//
	//
	// 
	ReadFile(hFile, &Chunk, sizeof(KEYFILE_FILEHEADER), &dwNumber, NULL);

	//
	// Make sure the Header it's fine.
	//
	if( Chunk.type != wFileHeader  || 
		Chunk.size != CALCULATE_KEYFILE_SIZE(bLoadModulus + bLoadEncKey + bLoadDecKey + bLoadXORKey) )
	{
		CloseHandle(hFile);
		return FALSE;
	}

	if( bLoadModulus != FALSE )
	{
		ReadFile(hFile, dwBuffer, sizeof(dwBuffer), &dwNumber, NULL);
		for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++ ) 
		{
			m_dwModulus[i] = s_dwSaveLoadXOR[i] ^ dwBuffer[i];
		}
	}

	if( bLoadEncKey != FALSE )
	{
		ReadFile(hFile, dwBuffer, sizeof(dwBuffer), &dwNumber, NULL);
		for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++ )
		{
			m_dwEncryptionKey[i] = s_dwSaveLoadXOR[i] ^ dwBuffer[i];
		}
	}

	if( bLoadDecKey != FALSE )
	{
		ReadFile(hFile, dwBuffer, sizeof(dwBuffer), &dwNumber, NULL);
		for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++ )
		{
			m_dwDecryptionKey[i] = s_dwSaveLoadXOR[i] ^ dwBuffer[i];
		}
	}

	if( bLoadXORKey != FALSE )
	{
		ReadFile(hFile, dwBuffer, sizeof(dwBuffer), &dwNumber, NULL);
		for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++ )
		{
			m_dwXORKey[i] = s_dwSaveLoadXOR[i] ^ dwBuffer[i];
		}
	}
	CloseHandle(hFile);
	return TRUE;
}

#ifdef SIMPLE_MODULUS_VERSION_1_1
//
//
// 
BOOL CSimpleModulus::LoadKeyFromBuffer(BYTE* pbyBuffer, BOOL bLoadModulus, BOOL bLoadEncKey, BOOL bLoadDecKey, BOOL bLoadXORKey)
{
	PDWORD pdwSeek = (PDWORD)pbyBuffer;

	if( bLoadModulus != FALSE )
	{
		for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++ )
		{
			m_dwXORKey[ i ] = pdwSeek[ i ] ^ s_dwSaveLoadXOR[ i ];
		}
		pdwSeek += sizeof(DWORD) * ENCRYPTION_KEY_SIZE;
	}

	if( bLoadEncKey != FALSE )
	{
		for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++ )
		{
			m_dwEncryptionKey[ i ] = pdwSeek[ i ] ^ s_dwSaveLoadXOR[ i ];
		}
		pdwSeek += sizeof(DWORD) * ENCRYPTION_KEY_SIZE;
	}

	if( bLoadDecKey != FALSE )
	{
		for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++ )
		{
			m_dwDecryptionKey[ i ] = pdwSeek[ i ] ^ s_dwSaveLoadXOR[ i ];
		}
		pdwSeek += sizeof(DWORD) * ENCRYPTION_KEY_SIZE;
	}

	if( bLoadXORKey != FALSE )
	{
		for( int i = 0; i < ENCRYPTION_KEY_SIZE; i++ )
		{
			m_dwXORKey[ i ] = pdwSeek[ i ] ^ s_dwSaveLoadXOR[ i ];
		}
		pdwSeek += sizeof(DWORD) * ENCRYPTION_KEY_SIZE;
	}

	return FALSE;
}

#endif // SIMPLE_MODULUS_VERSION_1_1
