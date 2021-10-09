# Open SSL Experiments for Blockchain

## Prerequisites

1. Bash/Zsh on Linux/Mac/WSL
2. OpenSSL on path

Note: 
> Password wherever applicable is set as `password`
> 
> The private keys stored hera are for demonstration purposes. Do not use any of the keys for any other purposes other than learning


## Options for `openssl`

```
Standard commands
asn1parse         ca                certhash          ciphers
crl               crl2pkcs7         dgst              dh
dhparam           dsa               dsaparam          ec
ecparam           enc               errstr            gendh
gendsa            genpkey           genrsa            nseq
ocsp              passwd            pkcs12            pkcs7
pkcs8             pkey              pkeyparam         pkeyutl
prime             rand              req               rsa
rsautl            s_client          s_server          s_time
sess_id           smime             speed             spkac
ts                verify            version           x509

Message Digest commands (see the `dgst' command for more details)
gost-mac          md4               md5               md_gost94
ripemd160         sha1              sha224            sha256
sha384            sha512            streebog256       streebog512
whirlpool

Cipher commands (see the `enc' command for more details)
aes-128-cbc       aes-128-ecb       aes-192-cbc       aes-192-ecb
aes-256-cbc       aes-256-ecb       base64            bf
bf-cbc            bf-cfb            bf-ecb            bf-ofb
camellia-128-cbc  camellia-128-ecb  camellia-192-cbc  camellia-192-ecb
camellia-256-cbc  camellia-256-ecb  cast              cast-cbc
cast5-cbc         cast5-cfb         cast5-ecb         cast5-ofb
chacha            des               des-cbc           des-cfb
des-ecb           des-ede           des-ede-cbc       des-ede-cfb
des-ede-ofb       des-ede3          des-ede3-cbc      des-ede3-cfb
des-ede3-ofb      des-ofb           des3              desx
rc2               rc2-40-cbc        rc2-64-cbc        rc2-cbc
rc2-cfb           rc2-ecb           rc2-ofb           rc4
rc4-40
```

Overwhelming? Refer to the concise table required for this tutorial

|Option|Description|
|------|-----------|
|[enc](https://www.openssl.org/docs/man1.1.1/man1/enc.html)|encryption, decryption, encoding and decoding (Symmetric encryption using AES algorithm)|
|[genpkey](https://www.openssl.org/docs/man1.1.1/man1/genpkey.html)|generate private key (using specified algorithm, ECDSA or RSA)|
|[pkey](https://www.openssl.org/docs/man1.1.1/man1/pkey.html)|process private and public keys|
|[dgst](https://www.openssl.org/docs/man1.1.1/man1/dgst.html)|digest using specified algorithm|
|[rsautl](https://www.openssl.org/docs/man1.1.1/man1/rsautl.html)|operations using RSA algorithm (asymmetric),like sign, verify, encrypt and decrypt using the RSA algorithm|
|[ecparam](https://www.openssl.org/docs/man1.1.1/man1/ecparam.html)|operations using ECDA curves using its parameters files|
|[genrsa](https://www.openssl.org/docs/man1.1.1/man1/genrsa.html)|generation of keys using RSA, superseded by `genpkey`|
|[req](https://www.openssl.org/docs/man1.1.1/man1/req.html)|creation of certificate and processes certificate requests|
|[x509](https://www.openssl.org/docs/man1.1.1/man1/x509.html)|operations for x509 type of certificates, like viewing, conversion, sign CSRs, edit certificate settings|
|[ca](https://www.openssl.org/docs/manmaster/man1/openssl-ca.html)|certificate authority operations (including generation of CSR, CRL, Approval)|
|[verify](https://www.openssl.org/docs/man1.1.1/man1/verify.html)|Verifies certificate chains|
|[crl](https://www.openssl.org/docs/man1.1.1/man1/crl.html)|Certification revocation management|


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

### Symmetric Encryption (Using AES)

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

### Asymmetric Encryption (Using RSA)

Generate RSA private key of 2048 bits

```shell
# generate without password
$ openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private-key.pem

#generate with password
$ openssl genpkey -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private-key-passwd.pem
```

Generate public key corresponding to the private key

```shell
openssl pkey -in public-key.pem -pubin -text
```

### Signature & Verification of data

```bash
# generate the hash of the data 
$ openssl dgst -sha256 data.txt > hash.txt

# generate the signature and store in a file
$ openssl rsautl -sign -inkey private-key.pem -keyform PEM -in hash.txt > signed.dat

# verify the signature of the data

$ HASH=$(openssl rsautl -verify -inkey public-key.pem -pubin -keyform PEM -in signed.dat)
$ [[ "$HASH" = "$(cat hash.txt)" ]] && echo 'sig matched' || echo "didn't match"
```

Alternate one liner approach without the script

```shell
$ openssl dgst -sha256 -sign private-key.pem -out somefile.sha256 randomfile.txt
$ openssl dgst -sha256 -verify public-key.pem -signature somefile.sha256 randomfile.txt
# in case of success: prints "Verified OK"
# in case of failure: prints "Verification Failure", return code 1

```



### ECDSA Asymmetric Key Management

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

> Using ECDSA keys for encryption with Openssl is not well documented and not well resourced. I will update this section on more updates.


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
6. https://www.feistyduck.com/library/openssl-cookbook/online/ch-openssl.html
7. https://stackoverflow.com/questions/10782826/digital-signature-for-a-file-using-openssl