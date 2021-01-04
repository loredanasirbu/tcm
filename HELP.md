# TCM project

### Bouncy castle VS Java Criptography Extension

For further reference, please consider the following sections:

JCE supported algorithms:

Opperation | Algorithm | Key Size (bits) | Mode | Padding Mode 
--- | --- | --- | --- |--- 
Cipher | AES | 128, 192, 256 | ECB, CBC | NOPADDING, PKCS5PADDING
Cipher | AES | 128, 192, 256 | CTR, CFB, GCM | PKCS5PADDING
Cipher | DES | 56 | ECB, CBC | NOPADDING, PKCS5PADDING 
Cipher | DESede | 168 | ECB, CBC | NOPADDING, PKCS5PADDING 
Cipher | TripleDES | 168 | ECB, CBC | NOPADDING, PKCS5PADDING 
Cipher | RSA | 1024, 2048 | ECB | PKCS5PADDING 
KeyGenerator | AES | 128, 192, 256 |  |  
KeyGenerator | DES | 56 |  |  
KeyGenerator | DESede | 168 |  |  
KeyGenerator | HmacSHA1 |  |  |  
KeyGenerator | HmacSHA256 |  |  |  
KeyGenerator | HmacSHA384 |  |  |  
KeyGenerator | HmacSHA512 |  |  |
KeyPairGenerator | RSA | 1024, 2048, 4096, 8192 |  |
KeyPairGenerator | EC |  | SecP192K1, SecP224K1, SecP256K1, NistP-192, NistP-224, NistP-256, NistP-384, NistP-512, Ed25519 |
Signature | RSA with SHA |  | SHA1withRSA, SHA256withRSA, SHA384withRSA, SHA512withRSA |  
Signature | EC with SHA |  | SHA1withECDSA, SHA256withECDSA, SHA384withECDSA, SHA512withECDSA |  
