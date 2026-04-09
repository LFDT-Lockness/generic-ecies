## v0.2.0

- Fixed panic in `EncryptedMessage::from_bytes` when given zero-length or too-short input (#7)
- Added `DeserializeError::TooShort` variant for graceful error handling on short inputs
- Replaced unchecked slice indexing with bounds-checked access in `from_bytes`

## v0.1.0

Initial release
