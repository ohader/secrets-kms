# CLAUDE.md

## Project

PHP library (`oliver-hader/secrets-kms`) that implements a file-backed key management store using libsodium. No runtime Composer dependencies.

- **Namespace**: `OliverHader\SecretsKms` (PSR-4, `src/`)
- **Tests namespace**: `OliverHader\SecretsKms\Tests` (PSR-4, `tests/`)
- **PHP**: 8.1+ (`#[\SensitiveParameter]` is silently ignored on 8.1, effective on 8.2+)
- **Test runner**: `vendor/bin/phpunit --testdox`

## Architecture

```
src/
  KeyEntry.php           Value object: PublicKey + comment + imported timestamp (for the `keys` list)
  KeyPair.php            X25519 key pair — generate, derive from seed, import
  PublicKey.php          Wraps raw 32-byte X25519 public key with base64url / multibase encoding
  SecretKey.php          Wraps raw 32-byte X25519 secret key; derives public key
  StorageInterface.php   load(): array / save(array): void
  Storage.php            File-backed JSON implementation
  Manager.php            All domain and public-key lifecycle operations
  Cipher.php             Symmetric encrypt/decrypt using a domain's data key
  Exception/
    RuntimeException.php       Base library exception
    DomainNotFoundException.php
    DecryptionException.php
```

### Crypto primitives (all libsodium, no external packages)

| Purpose | Function |
|---------|----------|
| Generate symmetric data key | `sodium_crypto_aead_xchacha20poly1305_ietf_keygen()` |
| Seal data key for a recipient | `sodium_crypto_box_seal($dataKey, $publicKey)` |
| Unseal data key | `sodium_crypto_box_seal_open($ciphertext, $keypair)` |
| Derive key pair from seed | `sodium_crypto_box_seed_keypair(sodium_crypto_generichash($seed, '', 32))` |
| Encrypt a value (Cipher) | `sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $domain, $nonce, $dataKey)` |
| Decrypt a value (Cipher) | `sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $domain, $nonce, $dataKey)` |
| Encode keys/ciphertexts | `sodium_bin2base64($bytes, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING)` |

### secrets.json structure

```json
{
    "keys": [
        {"publicKeyMultibase": "z<base64url-pubkey>", "comment": "Production key", "imported": "2024-01-01T01:02:30Z"}
    ],
    "domains": {
        "typo3/user-settings": {
            "keys": {
                "<base64url-pubkey>": "<base64url-sealed-data-key>"
            }
        }
    }
}
```

`publicKeyMultibase` = `z` prefix + base64url-no-padding encoding of the raw 32-byte public key.

`Storage::load()` always normalises both `keys` and `domains` to `[]` when absent.

### Key design rules

- `createDomain` auto-adds the caller's own key and all entries in `keys` — domain creator can never lock themselves out
- `reduceDomain` / `removePublicKeys` throw / skip silently if the caller's own key is passed — prevents self-lockout
- `extendDomain` requires the caller to have an existing sealed entry (needs own private key to re-seal for new recipients)
- `addPublicKeys` accepts `KeyEntry` objects, saves to `keys` first, then calls `extendAll` — if `extendAll` fails mid-way, the list is already updated (eventual consistency; no transactions)
- `addPublicKeys` deduplicates by `publicKeyMultibase`; subsequent calls with the same key are no-ops
- `KeyPair::getSodiumKeyPair()` returns `$secretKey . $publicKey` (64 bytes) — this matches sodium's internal layout expected by `seal_open`

## Exception error codes

| Code | Exception | Thrown by |
|------|-----------|-----------|
| 1778152622 | `RuntimeException` | `createDomain` — domain already exists |
| 1778152623 | `DomainNotFoundException` | `removeDomain` |
| 1778152624 | `RuntimeException` | `reduceDomain` — self-removal attempt |
| 1778152625 | `RuntimeException` | `resolvePublicKeyBytes` — wrong decoded length |
| 1778152626 | `DecryptionException` | `unsealDataKey` — own key not in domain |
| 1778152627 | `DecryptionException` | `unsealDataKey` — `seal_open` returned false |
| 1778152628 | `RuntimeException` | `Storage::load` — file unreadable |
| 1778152629 | `RuntimeException` | `Storage::load` — invalid JSON |
| 1778152630 | `RuntimeException` | `Storage::save` — file not writable |
| 1778152631 | `DomainNotFoundException` | `extendDomain` |
| 1778152632 | `DomainNotFoundException` | `reduceDomain` |
| 1778152633 | `RuntimeException` | `PublicKey::fromRawBytes` — wrong byte length |
| 1778152634 | `DecryptionException` | `Cipher::unsealWithDomainDataKey` — input too short (no room for nonce) |
| 1778152635 | `DecryptionException` | `Cipher::unsealWithDomainDataKey` — AEAD decryption failed |
| 1778152636 | `DomainNotFoundException` | `Service::getDataKey` |
| 1778152637 | `DecryptionException` | `Cipher::unsealWithDomainDataKey` — invalid base64 encoding |

## Coding conventions

- `declare(strict_types=1)` on every file
- `final` on all concrete classes
- `readonly` constructor promotion where applicable
- `#[\SensitiveParameter]` on all parameters carrying secret key material (`$seed`, `$secretKey`, `$rawSecretKey`, `$key` in Service constructor)
- `@` error suppression only on `file_get_contents` / `file_put_contents` in `Storage` — return value is always checked and re-thrown as a typed exception
- No comments unless the WHY is non-obvious

## Running tests

```bash
composer install
vendor/bin/phpunit --testdox
```

All 63 tests must pass with no warnings. Two tests (`testLoadThrowsOnUnreadableFile`, `testSaveThrowsOnUnwritableDirectory`) use `chmod` and skip themselves when running as root.
