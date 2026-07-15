## v0.3.0

- BREAKING: mark all errors as non-exhaustive. Future additional errors will not be a breaking change [#36]
- BREAKING: bump generic-ec version [#36]
- Properly zeroize all secrets derived during KEM [#36]

[#36]: https://github.com/LFDT-Lockness/generic-ecies/pull/?

## v0.2.0

- Fixed panic in `EncryptedMessage::from_bytes` when given zero-length or too-short input

## v0.1.0

Initial release
