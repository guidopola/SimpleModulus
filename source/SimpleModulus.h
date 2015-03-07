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
#ifndef SIMPLE_MODULUS_H_INCLUDED
#define SIMPLE_MODULUS_H_INCLUDED


#define ENCRYPTION_BLOCK_SIZE	8	
#define ENCRYPTION_KEY_SIZE		4	// ENCRYPTION_BLOCK_SIZE / 2
#define ENCRYPTED_BLOCK_SIZE	11



class CSimpleModulus 
{
public:
	CSimpleModulus();
	virtual ~CSimpleModulus();

	//
	// Info:	Initialize the Modulus Keys.
	// 
	void Init();

	//
	// Info:	Encrypt a block of memory.
	// Return:	The size of the encrypted block.
	// 
	int Encrypt(void* lpDest, void* lpSource, int iSize);

	//
	// Info:	Decrypt a block of memory.
	// Return:	The size of the decrypted block.
	// 
	int Decrypt(void* lpDest, void* lpSource, int iSize);

	//
	// Info:	Save the decryption and encryption keys to one 
	//			file.
	// Return:	TRUE on success.
	// 
	BOOL SaveAllKey(char* lpszFileName);

	//
	// Info:	Load both the encryption and decryption key's
	//			from a single key file.
	// Return:	TRUE on success.
	// 
	BOOL LoadAllKey(char* lpszFileName);

	//
	// Info:	Save a encryption-only key file. 
	//			This key is only used to encrypt the data.
	// Return:	TRUE on success.
	// 
	BOOL SaveEncryptionKey(char* lpszFileName);

	//
	// Info:	Load a encryption-only key file. 
	//			This key is only used to encrypt the data.
	// Return:	TRUE on success.
	// 
	BOOL LoadEncryptionKey(char* lpszFileName);

	//
	// Info:	Save a decryption-only key file. 
	//			This key is only used to decrypt the data.
	// Return:	TRUE on success.
	// 
	BOOL SaveDecryptionKey(char* lpszFileName);

	//
	// Info:	Load a decryption-only key file. 
	//			This key is only used to decrypt the data.
	// Return:	TRUE on success.
	// 
	BOOL LoadDecryptionKey(char* lpszFileName);

#ifdef SIMPLE_MODULUS_VERSION_1_1
	//
	// Info:	Load a key file from a buffer. 
	// Return:	TRUE on success.
	// 
	BOOL LoadKeyFromBuffer(BYTE* pbyBuffer, BOOL bLoadModulus, BOOL bLoadEncKey, BOOL bLoadDecKey, BOOL bLoadXORKey);
#endif

	//
	DWORD m_dwModulus[ENCRYPTION_KEY_SIZE];
	DWORD m_dwEncryptionKey[ENCRYPTION_KEY_SIZE];
	DWORD m_dwDecryptionKey[ENCRYPTION_KEY_SIZE];
	DWORD m_dwXORKey[ENCRYPTION_KEY_SIZE];

protected:

	//
	//
	// 
	void EncryptBlock(void* lpTarget, void* lpSource, int nSize);

	//
	//
	//
	int DecryptBlock(void* lpTarget, void* lpSource);

	//
	//
	//
	int AddBits(void* lpBuffer, int nNumBufferBits, void* lpBits, int nInitialBit, int nNumBits);

	//
	//
	// 
	void Shift(void* lpBuffer, int nByte, int nShift);

	//
	//
	// 
	int GetByteOfBit(int nBit);

	//
	//
	// 
	BOOL SaveKey(char* lpszFileName, WORD wFileHeader, BOOL bSaveModulus, BOOL bSaveEncKey, BOOL bSaveDecKey, BOOL bSaveXORKey);

	//
	//
	// 
	BOOL LoadKey(char* lpszFileName, WORD wFileHeader, BOOL bLoadModulus, BOOL bLoadEncKey, BOOL bLoadDecKey, BOOL bLoadXORKey);

	//
	//
	// 
	static DWORD s_dwSaveLoadXOR[ENCRYPTION_KEY_SIZE];
};

#endif // !SIMPLE_MODULUS_H_INCLUDED