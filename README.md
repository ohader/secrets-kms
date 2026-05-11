# secrets-kms

A PHP key management store backed by a local JSON file. It solves a specific multi-system problem: two or more systems (e.g. a TYPO3 production instance and a dev instance) each hold a different secret, but all systems need to read data encrypted under a shared symmetric key.

The approach: for each named **domain** (a logical scope like `typo3/user-settings`), a random symmetric data key is generated and then _sealed_ separately for every participating system's public key. Any system that holds the matching private key can unseal the data key for any domain it is registered in. No system ever sees another system's private key.

All cryptography is handled by [libsodium](https://doc.libsodium.org/) (`ext-sodium`), which ships with PHP 7.2+. No external Composer packages are required at runtime.

## Requirements

- PHP 8.1+ (suggested PHP 8.2+)
- `ext-sodium` (bundled with PHP, enabled by default)

## Installation

```bash
composer require oliver-hader/secrets-kms
```

## Core concepts

| Term | Meaning |
|------|---------|
| **KeyPair** | An X25519 asymmetric key pair. Can be generated randomly, derived deterministically from a password/secret, or imported from a raw secret key. |
| **Domain** | A named scope (e.g. `typo3/user-settings`). Each domain has one symmetric data key. |
| **Symmetric data key** | A 32-byte XChaCha20-Poly1305 key used for the actual data encryption in your application. |
| **Sealed entry** | The symmetric data key encrypted with one system's public key via `sodium_crypto_box_seal`. Only that system's private key can open it. |
| **Key entry** | A `KeyEntry` value object that pairs a public key with an optional `comment` and an `imported` timestamp. The persistent list of entries is stored under `keys` in `secrets.json` and is automatically included whenever a new domain is created. Managed via `addPublicKeys` / `removePublicKeys`. |
| **Storage** | A `secrets.json` file that holds all sealed entries for all domains. It contains no plaintext key material and is safe to commit to version control. |

## Quick start

### 1. Derive key pairs from each system's secret

The most common scenario for TYPO3: derive a key pair from the existing `encryptionKey`. The derivation is deterministic — the same secret always produces the same key pair.

```php
use OliverHader\SecretsKms\Key\KeyPair;
use OliverHader\SecretsKms\Manager;
use OliverHader\SecretsKms\Model\KeyEntry;
use OliverHader\SecretsKms\Storage;

// Each system derives its key pair from its own secret
$prodKeyPair = KeyPair::fromSeed('your-typo3-production-encryptionKey');
$devKeyPair  = KeyPair::fromSeed('your-typo3-dev-encryptionKey');
```

### 2. Register all participating systems upfront

Register public keys once so that every domain created afterwards grants access to all of them automatically.

```php
$storage = new Storage('/path/to/secrets.json');
$prodService = new Manager($prodKeyPair, $storage);

// Register the dev system — extends all existing domains and is remembered for future ones
$prodService->addPublicKeys(
    new KeyEntry($devKeyPair->getPublicKey(), comment: 'Dev instance'),
);
```

### 3. Create domains

```php
// Both prod and dev get access automatically because dev is in the `keys` list
$prodService->createDomain('typo3/user-settings');
$prodService->createDomain('typo3/registry-data');
```

The creator's own public key is always added automatically as well.

### 4. Dev system reads the domain's data key

```php
$devService = new Manager($devKeyPair, $storage);

// Both systems can independently retrieve the same underlying data key
// by unsealing their own entry in secrets.json.
// Use the data key in your application to encrypt/decrypt user data.
```

### 5. Add or remove systems later

```php
$stagingKeyPair = KeyPair::fromSeed('staging-encryptionKey');

// Register a new system — extends all existing domains and all future ones
$prodService->addPublicKeys(
    new KeyEntry($stagingKeyPair->getPublicKey(), comment: 'Staging instance'),
);

// Deregister a system — removes it from all existing domains and the keys list
$prodService->removePublicKeys(
    $devKeyPair->getPublicKey(),
);
```

For finer control without touching the auto list:

```php
// Grant access to one domain only
$prodService->extendDomain('typo3/user-settings', $stagingKeyPair->getPublicKey());

// Revoke access from one domain only
$prodService->reduceDomain('typo3/user-settings', $stagingKeyPair->getPublicKey());
```

### 6. Inspect registered data

```php
$prodService->listDomains();
// ['typo3/user-settings', 'typo3/registry-data']

$prodService->listPublicKeys();
// [KeyEntry($devPublicKey, comment: 'Dev instance', imported: ...)]
```

## Full API

```php
$manager = new Manager(string|KeyPair $key, StorageInterface $storage);
```

Passing a `string` is equivalent to `KeyPair::fromSeed($string)`.

### Domain management

| Method | Description |
|--------|-------------|
| `createDomain(string $name, PublicKey ...$publicKeys): void` | Generates a fresh symmetric data key and seals it for the given public keys, all registered `keys` entries, and the caller's own key. Throws if the domain already exists. |
| `removeDomain(string $name): void` | Deletes the domain and all its sealed entries. |
| `extendDomain(string $name, PublicKey ...$publicKeys): void` | Seals the existing data key for additional public keys. The caller must already have access. Skips keys already present. |
| `reduceDomain(string $name, PublicKey ...$publicKeys): void` | Removes sealed entries for the given public keys. The caller's own key cannot be removed. |
| `extendAll(PublicKey ...$publicKeys): void` | Calls `extendDomain` for every registered domain. |
| `reduceAll(PublicKey ...$publicKeys): void` | Calls `reduceDomain` for every registered domain. |
| `listDomains(): array` | Returns all registered domain names. |

### Key list management

| Method | Description |
|--------|-------------|
| `addPublicKeys(KeyEntry ...$entries): void` | Persists the entries to the `keys` list and calls `extendAll` so all existing domains get access too. Deduplicates by `publicKeyMultibase`; idempotent for the same key. |
| `removePublicKeys(PublicKey ...$publicKeys): void` | Removes matching entries from the `keys` list and calls `reduceAll` to revoke access from all existing domains. The caller's own key is silently skipped. |
| `listPublicKeys(): KeyEntry[]` | Returns all entries currently in the `keys` list. |

## KeyPair construction

```php
// Random — useful for generating a fresh dedicated key pair
$kp = KeyPair::generate();

// Deterministic from a password or existing secret (e.g. TYPO3 encryptionKey)
$kp = KeyPair::fromSeed('any string of any length');

// From raw 32-byte secret key bytes (import an existing key)
$kp = KeyPair::fromSecretKey($rawSecretKeyBytes);
```

Share `$kp->getPublicKeyEncoded()` (a URL-safe base64 string) with other systems so they can grant access to domains. Keep `$kp->getSecretKey()` private.

## Custom storage

`Manager` accepts any `StorageInterface` implementation, so you can swap the file-backed `Storage` for a database, a remote key-value store, or an in-memory stub for tests.

```php
use OliverHader\SecretsKms\StorageInterface;
use OliverHader\SecretsKms\Model\SecretsData;

class DatabaseStorage implements StorageInterface
{
    public function load(): SecretsData { /* ... */ }
    public function save(SecretsData $data): void { /* ... */ }
}
```

## What secrets.json looks like

The file has two top-level sections: `keys` (the list of persistently registered systems) and `domains` (one entry per scope, each containing sealed data key entries per system).

Each entry in `keys` is an object with:
- `publicKeyMultibase` — `z` prefix + URL-safe base64-no-padding encoding of the raw 32-byte X25519 public key
- `comment` — arbitrary label, may be empty
- `imported` — UTC ISO 8601 timestamp recording when the entry was added

The map keys inside each domain are URL-safe base64-encoded X25519 public keys (32 bytes); the values are URL-safe base64-encoded sealed ciphertexts (80 bytes: 32-byte ephemeral public key + 16-byte MAC + 32-byte data key).

```json
{
    "keys": [
        {
            "publicKeyMultibase": "zHlQsvSs1PqVOygDf1G4NXY1WmyokQGGuxv__C9z7tlU",
            "comment": "Dev instance",
            "imported": "2024-01-01T01:02:30Z"
        }
    ],
    "domains": {
        "typo3/user-settings": {
            "keys": {
                "HlQsvSs1PqVOygDf1G4NXY1WmyokQGGuxv__C9z7tlU": "CC_teJ2kEUK3vvFQvEn9eEso_gHgY4cfnsCCkvseyyrZEW-DhTyNbipbIhBS-qV8zNPCTTcgV69hNjqOZJ7xsKf98VV2RBbPvzTh2-2auso",
                "r61s2kH6Omi2yD7V65ki2WNum75HAYO9GF3jE25Zzis": "YldmDnbaLY4uSX1Y-UwqS0NLvwYKzCNMyMENWGgL_1UWRAKr3-SEycOpEo67bKLjWImfyCP9jvzDEYFSu4l_yR-zYfd0X61TBJqotuMeSZg"
            }
        },
        "typo3/registry-data": {
            "keys": {
                "r61s2kH6Omi2yD7V65ki2WNum75HAYO9GF3jE25Zzis": "XmbYyMx-FqZTCVh6SwRHfl7-cPUBXSXTzgRRcGelLnmIAxg-kzcX6QkIndmsk9JBXKTQJ1XOLs5aqUELqDgNRXZzKd4drSH5zwNzKp5N99c"
            }
        }
    }
}
```

In this example:
- `HlQsvSs1…` is the dev system's public key — in `keys` (as `zHlQsvSs1…`) and registered in `typo3/user-settings`
- `r61s2kH6…` is the production system's public key — registered in both domains
- `typo3/registry-data` has only the production key because dev was removed from that domain after creation

The file contains no plaintext secrets. It is safe to commit to version control, store in a shared config repository, or sync across systems — any system that does not hold a matching private key learns nothing from reading it.

## Running the tests

```bash
composer install
vendor/bin/phpunit --testdox
```
