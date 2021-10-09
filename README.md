# Open SSL Experiments for Blockchain

## Prerequisites

1. Bash/Zsh on Linux/Mac/WSL
2. OpenSSL on path

Note: 
> Password wherever applicable is set as `password`
> 
> The private keys stored hera are for demonstration purposes. Do not use any of the keys for any other purposes other than learning

## Hashing

```shell
$ openssl dgst -md5 randomfile.txt
MD5(randomfile.txt)= 94c6d25ee9a9774b89d3d2c6c702f771
```
```shell
$ openssl dgst -sha1 randomfile.txt
SHA1(randomfile.txt)= ce57fa48fe3b1e51061e45444a705e83a9074f7d
```
```shell
$ openssl dgst -sha512 randomfile.txt
SHA512(randomfile.txt)= 04cec29bb327757df3431e5ff75a24dda4cf62a9167667de8f42bebbcb1aef34785cdee2a2ba88ff6999264374c23e425370d0a685b440277ac7f61ee859e88b
```

Options for `dgst` are: 
```shell
-c              to output the digest with separating colons
-r              to output the digest in coreutils format
-d              to output debug info
-hex            output as hex dump
-binary         output in binary form
-sign   file    sign digest using private key in file
-verify file    verify a signature using public key in file
-prverify file  verify a signature using private key in file
-keyform arg    key file format (PEM)
-out filename   output to filename rather than stdout
-signature file signature to verify
-sigopt nm:v    signature parameter
-hmac key       create hashed MAC with key
-mac algorithm  create MAC (not neccessarily HMAC)
-macopt nm:v    MAC algorithm parameters or key
-gost-mac       to use the gost-mac message digest algorithm
-streebog512    to use the streebog512 message digest algorithm
-streebog256    to use the streebog256 message digest algorithm
-md_gost94      to use the md_gost94 message digest algorithm
-md4            to use the md4 message digest algorithm
-md5            to use the md5 message digest algorithm
-md5-sha1       to use the md5-sha1 message digest algorithm
-ripemd160      to use the ripemd160 message digest algorithm
-sha1           to use the sha1 message digest algorithm
-sha224         to use the sha224 message digest algorithm
-sha256         to use the sha256 message digest algorithm
-sha384         to use the sha384 message digest algorithm
-sha512         to use the sha512 message digest algorithm
-whirlpool      to use the whirlpool message digest algorithm
```

## Encryption and Decryption

### Symmetric Encryption

Encryption using `aes-128-cbc` & `aes-256-cbc` algorithm

```shell
$ openssl enc -aes-128-cbc -e -salt -in randomfile.txt -out randomfile_enc.txt
$ openssl enc -aes-256-cbc -e -salt -in randomfile.txt -out randomfile_enc_aes-256-cbc.txt
```

Decryption using `aes-128-cbc` and `aes-256-cbc`

```shell
$ openssl enc -aes-128-cbc -d -in randomfile_enc.txt -out randomfile_dec.txt
$ openssl enc -aes-256-cbc -d -in randomfile_enc.txt -out randomfile_dec_aes256cbc.txt
```

### Asymmetric Encryption

Generate Elliptic Curve of `secp256k1` type

```shell
$ openssl ecparam -name secp256k1 -out prime_secp256k1.pem
$ openssl genpkey -aes256 -paramfile prime_secp256k1.pem -out private_key.pem
```

Generate the private key
```shell
$ openssl genpkey -aes256 -paramfile prime_secp256k1.pem -out private_key.pem
```
Generate the public key from the private key above
```shell
$ openssl pkey -in private_key.pem -out public-key.pem -pubout
```

Alternate direct way
```shell
# generate private key
$ openssl ecparam -name prime256v1 -genkey -noout -out private_key_direct.pem

# generate corresponding public key
$ openssl ec -in private_key_direct.pem -pubout -out public_key_direct.pem
```

# PART 2

Please refer from here: 
https://jamielinux.com/docs/openssl-certificate-authority/index.html

## Creation of Party

1. Creation of CSR
2. Signing of the CSR with the root CA
3. Signing of CSR with intermediate CA

## Verification of Root of trust

1. Inspect certificate contents
2. Verify if a certificate belongs to a chain
3. Verify if a certificate do not belong to a chain

## Certificate Revocation

1. Addition to CRL
2. Validating if the certificate is rejected
3. Sign some data with the certificate

## References

1. https://www.keycdn.com/blog/openssl-tutorial
2. https://wiki.openssl.org/index.php/Command_Line_Utilities
3. https://www.openssl.org/docs/man1.1.0/man1/genpkey.html
4. https://www.scottbrady91.com/openssl/creating-elliptical-curve-keys-using-openssl
5. https://www.ibm.com/support/pages/openssl-commands-check-and-verify-your-ssl-certificate-key-and-csr