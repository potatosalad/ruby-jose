## Support algorithms for signing and encryption

Here are the options for the `alg` claim, grouped by similar funcionality:

- Single Asymmetric Public/Private Key Pair
  - `RSA1_5`
  - `RSA-OAEP`
  - `RSA-OAEP-256`
- Two Asymmetric Public/Private Key Pairs with Key Agreement
  - `ECDH-ES`
  - `ECDH-ES+A128KW`
  - `ECDH-ES+A192KW`
  - `ECDH-ES+A256KW`
- Symmetric Password Based Key Derivation
  - `PBES2-HS256+A128KW`
  - `PBES2-HS384+A192KW`
  - `PBES2-HS512+A256KW`
- Symmetric Key Wrap
  - `A128GCMKW`
  - `A192GCMKW`
  - `A256GCMKW`
  - `A128KW`
  - `A192KW`
  - `A256KW`
- Symmetric Direct Key (known to both sides)
  - `dir`

Here are the options for the `enc` claim:
  - `A128CBC-HS256`
  - `A192CBC-HS384`
  - `A256CBC-HS512`
  - `A128GCM`
  - `A192GCM`
  - `A256GCM`
