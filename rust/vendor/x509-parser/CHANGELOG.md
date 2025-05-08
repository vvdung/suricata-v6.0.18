# Change Log

## [Unreleased][unreleased] 

### Added/Changed/Fixed

### Thanks

## 0.8.2

- Objects: add OID for domainComponent
- X509Name: relax check, allow some non-rfc compliant strings (#50)

## 0.8.1

- Upgrade base64 requirement from 0.12 to 0.13
- Add PartialEq to X509Error
- Add helper methods to X509Name and simplify accessing values (#50)

### Thanks

## 0.8.0

### Added/Changed

- Upgrade to `der-parser` 4.0
- Move from `time` to `chrono`
  - `time 0.1 is very old, and time 0.2 broke compatibility and cannot parse timezones
  - Add public type `ASN1Time` object to abstract implementation
  - *this breaks API for direct access to `not_before`, `not_after` etc.*
- Fix clippy warnings
  - `nid2obj` argument is now passed by copy, not reference
- Add method to get a formatted string of the certificate serial number
- Add method to get decoded version
- Add convenience methods to access the most common fields (subject, issuer, etc.)
- Expose the raw DER of an X509Name
- Make `parse_x509_name` public, for parsing distinguished names
- Make OID objects public
- Implement parsing for some extensions
  - Support for extensions is not complete, support for more types will be added later
- Add example to decode and print certificates
- Add `verify` feature to verify cryptographic signature by a public key

### Fixed

- Fix parsing of types not representable by string in X509Name (#36)
- Fix parsing of certificates with empty subject (#37)

### Thanks

- @jannschu, @g2p for the extensions parsing
- @wayofthepie for the tests and contributions
- @nicholasbishop for contributions

## 0.7.0

- Expose raw bytes of the certificate serial number
- Set edition to 2018

## 0.6.4

- Fix infinite loop when certificate has no END mark

## 0.6.3

- Fix infinite loop when reading non-pem data (#28)

## 0.6.2

- Remove debug code left in `Pem::read`

## 0.6.1

- Add CRL parser
- Expose CRL tbs bytes
- PEM: ignore lines before BEGIN label (#21)
- Fix parsing default values for TbsCertificate version field (#24)
- Use BerResult from der-parser for simpler function signatures
- Expose tbsCertificate bytes
- Upgrade dependencies (base64)

## 0.6.0

- Update to der-parser 3.0 and nom 5
- Breaks API, cleaner error types

## 0.5.1

- Add `time_to_expiration` to `Validity` object
- Add method to read a `Pem` object from `BufRead + Seek`
- Add method to `Pem` to decode and extract certificate

## 0.5.0

- Update to der-parser 2.0

## 0.4.3

- Make `parse_subject_public_key_info` public
- Add function `sn2oid` (get an OID by short name)

## 0.4.2

- Support GeneralizedTime conversion

## 0.4.1

- Fix case where certificate has no extensions

## 0.4.0

- Upgrade to der-parser 1.1, and Use num-bigint over num
- Rename x509_parser to parse_x509_der
- Do not export subparsers
- Improve documentation

## 0.3.0

- Upgrade to nom 4

## 0.2.0

- Rewrite X.509 structures and parsing code to work in one pass
  **Warning: this is a breaking change**
- Add support for PEM-encoded certificates
- Add some documentation


