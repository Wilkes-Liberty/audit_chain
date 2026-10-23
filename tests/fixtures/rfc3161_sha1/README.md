# SHA-1 RFC 3161 signer fixture

Negative-test certificates only. `Rfc3161FixtureFactory` loads these
when the variant is `sha1` so the algorithm-floor test can still reject
a SHA-1 TSA under an OpenSSL 3 FIPS provider, which refuses to mint
SHA-1 signatures.

`root.pem` is a 2048-bit RSA CA. `tsa.pem` is a timeStamping leaf.
`tsa.key` is the matching unencrypted private key used to CMS-sign the
fixture token with SHA-256. None of these are a real TSA.
