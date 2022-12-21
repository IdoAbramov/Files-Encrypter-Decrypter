#include <iostream>
#include <vector>
#include <string>
#include <array>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#pragma comment (lib, "bcrypt.lib")
#pragma comment (lib, "ws2_32.lib")

// Checks the status returned from WinAPI functions. Negative status is an error.
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0) 

// return code status
enum ReturnCode { SUCCESS = 0, FAILED = 1 };

constexpr int KEY_LENGTH = 16;
constexpr int ENCRYPTED_KEY_LENGTH = 128;

// Plain private key on the server-side. might change to pick from a file.
BYTE PrivateKey[] = { 0x52, 0x53, 0x41, 0x32, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x40, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xB7, 0x50, 0x52, 0xDD, 0x58, 0xE4, 0x96, 0xAF, 0x91, 0xE5, 0xB2, 0x7B, 0x0A, 0xE6, 0xAA,
    0x1F, 0x71, 0x8A, 0x66, 0xC3, 0xF0, 0x21, 0xD8, 0xE6, 0x2C, 0xD6, 0x25, 0x2E, 0x77, 0x3C, 0x61, 0x08, 0x1B, 0x69, 0xE7, 0x58, 0xDF, 0x3B, 0x07,
    0xFE, 0xF1, 0xDB, 0xBF, 0xA6, 0x35, 0xDF, 0xC7, 0x49, 0x06, 0xC8, 0xDB, 0x74, 0x2A, 0xB9, 0xED, 0xB3, 0x04, 0x80, 0x75, 0x5F, 0x71, 0x2C, 0xD0,
    0x14, 0x0E, 0x81, 0x18, 0x00, 0x5E, 0x34, 0x5A, 0xC2, 0x3A, 0x84, 0x63, 0xB1, 0x6B, 0x04, 0x21, 0x49, 0x7F, 0xE0, 0xF3, 0x52, 0x5E, 0x61, 0x43,
    0xB1, 0x8F, 0x7C, 0xF2, 0x74, 0x29, 0x28, 0x69, 0x20, 0x36, 0xC0, 0x92, 0x17, 0x42, 0x99, 0x72, 0xE5, 0xE7, 0x82, 0xBE, 0x8E, 0x3B, 0x3F, 0xC9,
    0x0A, 0xE1, 0xC4, 0x63, 0x68, 0x73, 0x1D, 0x67, 0x8D, 0xC0, 0xA3, 0xB4, 0xBA, 0xF0, 0xB7, 0xB0, 0x9B, 0xBB, 0x3F, 0xB8, 0x6E, 0xC0, 0x34, 0x1E,
    0xA0, 0x01, 0x4B, 0x6D, 0x47, 0x73, 0x3F, 0xA5, 0x39, 0x05, 0x27, 0xD4, 0xD1, 0x38, 0x34, 0x32, 0x2C, 0x5B, 0x03, 0x5F, 0x16, 0x21, 0x64, 0x04,
    0xD5, 0x19, 0xDB, 0xE7, 0x80, 0xDA, 0xBD, 0xC4, 0x1E, 0xAB, 0x61, 0xC8, 0x84, 0xDF, 0x54, 0x16, 0x77, 0x98, 0x9B, 0x90, 0x03, 0x83, 0xC4, 0x8D,
    0x25, 0xB1, 0x32, 0x67, 0x77, 0x6A, 0x1C, 0x64, 0x2D, 0xFA, 0x9E, 0xB9, 0x26, 0xB5, 0xF8, 0x47, 0x4A, 0x9C, 0x35, 0x89, 0x5F, 0x12, 0x0E, 0xFF,
    0x60, 0x87, 0x1E, 0x27, 0xC1, 0xC5, 0x7C, 0x77, 0x0A, 0xAE, 0x11, 0x37, 0xE3, 0x42, 0x9B, 0xAF, 0x9D, 0xBC, 0xC2, 0x52, 0xF8, 0x85, 0xBA, 0xED,
    0x8E, 0xC3, 0x73, 0x04, 0x0A, 0x53, 0xD2, 0x1D, 0xEF, 0xA0, 0x6A, 0xCD, 0xBE, 0x93, 0x49, 0x34, 0x3A, 0xBD, 0xDF, 0x6A, 0x33, 0x25, 0x91, 0xFC, 0xE7 };


ReturnCode decryptSymmetricKey(std::array<BYTE, ENCRYPTED_KEY_LENGTH>& encryptedKey,
                               std::array<BYTE, KEY_LENGTH>& decryptedKey);

int main() {

    std::cout << "\n Starting server...\n\n";

    WSADATA              wsaData;
    int                  iResult;

    SOCKET               ListenSocket = INVALID_SOCKET,
                         ClientSocket = INVALID_SOCKET;

    struct addrinfo*     result = NULL;
    struct addrinfo      hints;

    PCSTR psServerPort = "27000";

    std::array<BYTE, ENCRYPTED_KEY_LENGTH> encryptedKey = { 0 };
    std::array<BYTE, KEY_LENGTH> decryptedKey = { 0 };

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "<ERROR> WSAStartup failed with error: " << iResult << "\n";
        return ReturnCode::FAILED;
    }

    SecureZeroMemory(&hints, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, 
                          psServerPort, 
                          &hints, 
                          &result);

    if (iResult != 0) {
        std::cerr << "<ERROR> getaddrinfo failed with error: " << iResult << "\n";
        WSACleanup();
        return ReturnCode::FAILED;
    }

    // Create a SOCKET for the server to listen for client connections.
    ListenSocket = socket(result->ai_family,
                          result->ai_socktype,
                          result->ai_protocol);

    if (ListenSocket == INVALID_SOCKET) {
        std::cerr << "<ERROR> socket failed with error: " << WSAGetLastError() << "\n";
        freeaddrinfo(result);
        WSACleanup();
        return ReturnCode::FAILED;
    }


    // Setup the TCP listening socket
    iResult = bind(ListenSocket,
                   result->ai_addr, 
                   (int)result->ai_addrlen);

    if (iResult == SOCKET_ERROR) {
        std::cerr << "<ERROR> bind failed with error: " << WSAGetLastError() << "\n";
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return ReturnCode::FAILED;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);

    if (iResult == SOCKET_ERROR) {
        std::cerr << "<ERROR> listen failed with error: " << WSAGetLastError() << "\n";
        closesocket(ListenSocket);
        WSACleanup();
        return ReturnCode::FAILED;
    }

    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);

    if (ClientSocket == INVALID_SOCKET) {
        std::cerr << "<ERROR> accept failed with error: " << WSAGetLastError() << "\n";
        closesocket(ListenSocket);
        WSACleanup();
        return ReturnCode::FAILED;
    }

    closesocket(ListenSocket);

    iResult = recv(ClientSocket,
                   (char*)encryptedKey.data(),
                   ENCRYPTED_KEY_LENGTH, 
                   0);

    if (iResult == SOCKET_ERROR) {
        std::cerr << "<ERROR> recv failed with error: " << WSAGetLastError() << "\n";
        closesocket(ClientSocket);
        WSACleanup();
        return ReturnCode::FAILED;
    }

    decryptSymmetricKey(encryptedKey,
                        decryptedKey); 

    // Sends the decrypted key back to the client.
    iResult = send(ClientSocket,
                   (char*)decryptedKey.data(),
                   KEY_LENGTH, 
                   0);

    if (iResult == SOCKET_ERROR) {
        std::cerr << "<ERROR> send failed with error: " << WSAGetLastError() << "\n";
        closesocket(ClientSocket);
        WSACleanup();
        return ReturnCode::FAILED;
    }

    // shutdown the connection since we're done
    iResult = shutdown(ClientSocket, SD_SEND);

    if (iResult == SOCKET_ERROR) {
        std::cerr << "<ERROR> shutsown failed with error: " << WSAGetLastError() << "\n";
        closesocket(ClientSocket);
        WSACleanup();
        return ReturnCode::FAILED;
    }

    // cleanup
    closesocket(ClientSocket);
    WSACleanup();

    return ReturnCode::SUCCESS;
}

ReturnCode decryptSymmetricKey(std::array<BYTE, ENCRYPTED_KEY_LENGTH>& encryptedKey,
                               std::array<BYTE, KEY_LENGTH>& decryptedKey) {

    BCRYPT_ALG_HANDLE   hRsaAlg = NULL;

    BCRYPT_KEY_HANDLE   hKey = NULL;

    NTSTATUS            status = 0;

    ReturnCode          returnCode = ReturnCode::SUCCESS;

    PBYTE               pbEncryptedBuffer = NULL,
                        pbDecryptedBuffer = NULL;

    DWORD               cbEncryptedBuffer = 0,
                        cbDecryptedBuffer = 0,
                        dwNumOfBytesWritten = 0;

    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hRsaAlg,
                                                         BCRYPT_RSA_ALGORITHM,
                                                         NULL,
                                                         0))) {
        std::cerr << "<ERROR> Failed to get algorithm provider.\n";
        returnCode = ReturnCode::FAILED;
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptImportKeyPair(hRsaAlg,
                                                 NULL,
                                                 BCRYPT_RSAPRIVATE_BLOB,
                                                 &hKey,
                                                 PrivateKey,
                                                 sizeof(PrivateKey),
                                                 BCRYPT_NO_KEY_VALIDATION))) {
        std::cerr << "<ERROR> Failed to import Private key.\n";
        returnCode = ReturnCode::FAILED;
        goto Cleanup;
    }

    pbEncryptedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 
                                         HEAP_ZERO_MEMORY,
                                         ENCRYPTED_KEY_LENGTH);

    if (pbEncryptedBuffer == NULL) {
        std::cerr << "<ERROR> Failed to allocate memory on the heap.\n";
        returnCode = ReturnCode::FAILED;
        goto Cleanup;
    }

    memcpy_s(pbEncryptedBuffer,
             ENCRYPTED_KEY_LENGTH,
             encryptedKey.data(),
             ENCRYPTED_KEY_LENGTH);

    if (!NT_SUCCESS(status = BCryptDecrypt(hKey,
                                           pbEncryptedBuffer,
                                           ENCRYPTED_KEY_LENGTH,
                                           NULL,
                                           NULL,
                                           0,
                                           NULL,
                                           0,
                                           &cbDecryptedBuffer,
                                           BCRYPT_PAD_PKCS1))) {
        std::cerr << "<ERROR> Failed to get required size of buffer.\n";
        returnCode = ReturnCode::FAILED;
        goto Cleanup;
    }

    // Allocate memory for the decrypted key.
    pbDecryptedBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(),
                                          HEAP_ZERO_MEMORY,
                                          cbDecryptedBuffer);

    if (pbDecryptedBuffer == NULL) {
        printf("<ERROR> Failed to allocate memory on the heap.\n");
        returnCode = ReturnCode::FAILED;
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptDecrypt(hKey,
                                           pbEncryptedBuffer,
                                           ENCRYPTED_KEY_LENGTH,
                                           NULL,
                                           NULL,
                                           0,
                                           pbDecryptedBuffer,
                                           cbDecryptedBuffer,
                                           &cbDecryptedBuffer,
                                           BCRYPT_PAD_PKCS1))) {
        std::cerr << "<ERROR> Failed to perform symmetric key decryption.\n";
        returnCode = ReturnCode::FAILED;
        goto Cleanup;
    }

    memcpy_s(decryptedKey.data(),
             KEY_LENGTH, 
             pbDecryptedBuffer,
             KEY_LENGTH);
    
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
