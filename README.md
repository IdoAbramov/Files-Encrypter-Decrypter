# Files-Encrypter-Decrypter
Secure files with AES &amp; RSA encryption.

C++ with WinAPI and Windows CNG.

Use FilesEncrypter >> to encrypt all files under given directory (recursively).

The files encrypted by AES random generated key which is encrypted by RSA public key, and saved in "enckey.bin" file.


Use FilesDecrypterClient >> to decrypt all files under given directory (recursively).

The client sends the encrypted AES symmetric key to the FilesDecrypterServer to decrypt it.

The server returns the decrypted AES symmetric key which is used to decrypt all the files.


Use FilesDecrypterServer >> to decrypt the AES symmetric key with RSA private key and return it to the client.

