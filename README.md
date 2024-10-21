# generic-ecies

ECIES is a scheme for efficient ciphers with asymmetric key using elliptic
curves and symmetric ciphers. This implementation is generic in its components,
thanks to using [`generic_ec`](https://docs.rs/generic-ec) and
[`RustCrypto`](https://github.com/RustCrypto) traits. You can use the
ciphersuites defined by us in advance, like `curve25519xsalsa20hmac` and
`curve25519aes128_cbchmac`, or you can define your own.

This implementation is based on [SECG SEC-1](http://www.secg.org/sec1-v2.pdf)

For more information and examples, see the [docs page](https://docs.rs/generic-ecies)
