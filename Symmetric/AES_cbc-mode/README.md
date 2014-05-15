Ref: http://www.cs.stevens.edu/~nicolosi/classes/14sp-cs579/lab1/lab1.html

This is one of my assignment for course CS579 Foundations of Cryptography at Stevens.

<backquote>
The utility will allow you to generate a symmetric encryption/decryption key for an Adaptive Chosen-Ciphertext (CCA) secure Symmetric-Key Encryption scheme. You can then encrypt your files so that only you (and those to whom you give the symmetric key) can recover the original plaintext.
</backquote>

## Requirement

see: http://www.cs.stevens.edu/~nicolosi/classes/14sp-cs579/lab0/install-libs.html

__GNU MP__
GNU Multiple Precision arithmetic library
The gmp library provides support for big integers and many number-theoretics functions, which are needed for the implementation of most cryptographic primitives. 

__Libdcrypt__
Download dcrypt from [libdcrypt-0.6.tar.gz](http://www.cs.stevens.edu/~nicolosi/classes/14sp-cs579/lab0/libdcrypt-0.6.tar.gz).

## Implementation

Cipher-Block Chaining (CBC). To encrypt in CBC mode, one thinks of the stream of bytes as a sequence of block, each of the size of the block cipher being used (AES in your case); then, one XORs each plaintext block with the encryption of the previous block before encrypting, as shown here: 

![AES CBC-mode](./CBC.gif)

If the plaintext blocks are m1, m2, ..., and the ciphertext blocks c1, c2, ..., then encryption and decryption in CBC mode are performed as follows:
<blockquote>
<p>
c<sub>i</sub> = E(m<sub>i</sub> XOR c<sub>i-1</sub>)<br>
m<sub>i</sub> = D(c<sub>i</sub>) XOR c<sub>i-1</sub>
</p></blockquote>

## Usage

### Key Generation
$ ./pv_keygen my_key.b64 

### Encrypt

$ ./pv_encrypt my_key.b64 a_file an_encrypted_file

### Decrypt

$ ./pv_decrypt my_key.b64 an_encrypted_file a_decrypted_file

### Result

$ diff a_file a_decrypted_file


