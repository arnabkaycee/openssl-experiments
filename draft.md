openssl list-standard-commands
openssl list-cipher-commands


Generate prime numbers

`openssl prime -generate -bits 1024`




openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private-key.pem