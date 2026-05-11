<?php

declare(strict_types=1);

namespace OliverHader\SecretsKms;

use OliverHader\SecretsKms\Exception\DecryptionException;
use OliverHader\SecretsKms\Exception\DomainExistsException;
use OliverHader\SecretsKms\Exception\DomainNotFoundException;
use OliverHader\SecretsKms\Exception\InvalidKeyMaterialException;
use OliverHader\SecretsKms\Exception\SelfLockoutException;

final class Manager
{
    private KeyPair $keyPair;

    public function __construct(
        #[\SensitiveParameter]
        string|KeyPair $key,
        private readonly StorageInterface $storage,
    ) {
        $this->keyPair = $key instanceof KeyPair ? $key : KeyPair::fromSeed($key);
    }

    public function hasDomain(string $name): bool
    {
        return isset($this->storage->load()['domains'][$name]);
    }

    public function createDomain(string $name, PublicKey ...$publicKeys): void
    {
        $data = $this->storage->load();

        if ($this->hasDomain($name)) {
            throw new DomainExistsException(
                sprintf('Domain "%s" already exists', $name),
                1778152622,
            );
        }

        $dataKey = sodium_crypto_aead_xchacha20poly1305_ietf_keygen();

        // Build encoded → PublicKey map; array keys deduplicate automatically.
        $recipients = [];
        foreach ($publicKeys as $pk) {
            $recipients[$pk->getEncoded()] = $pk;
        }
        foreach ($data['keys'] as $entry) {
            $pk = KeyEntry::fromArray($entry)->publicKey;
            $recipients[$pk->getEncoded()] ??= $pk;
        }
        $ownPublicKey = $this->keyPair->getPublicKey();
        $recipients[$ownPublicKey->getEncoded()] ??= $ownPublicKey;

        $keysMap = array_map(
            fn(PublicKey $pk): string => $this->sealDataKey($dataKey, $pk),
            $recipients
        );

        $data['domains'][$name] = ['keys' => $keysMap];
        $this->storage->save($data);
    }

    public function removeDomain(string $name): void
    {
        $data = $this->storage->load();

        if (!$this->hasDomain($name)) {
            throw new DomainNotFoundException(
                sprintf('Domain "%s" not found', $name),
                1778152623,
            );
        }

        unset($data['domains'][$name]);
        $this->storage->save($data);
    }

    public function extendDomain(string $name, PublicKey ...$publicKeys): void
    {
        $data = $this->storage->load();

        if (!$this->hasDomain($name)) {
            throw new DomainNotFoundException(
                sprintf('Domain "%s" not found', $name),
                1778152631,
            );
        }

        $dataKey = $this->unsealDataKey($data['domains'][$name], $this->keyPair->getPublicKeyEncoded());

        foreach ($publicKeys as $pk) {
            $encodedKey = $pk->getEncoded();
            if (isset($data['domains'][$name]['keys'][$encodedKey])) {
                continue;
            }
            $data['domains'][$name]['keys'][$encodedKey] = $this->sealDataKey($dataKey, $pk);
        }

        $this->storage->save($data);
    }

    public function reduceDomain(string $name, PublicKey ...$publicKeys): void
    {
        $data = $this->storage->load();

        if (!$this->hasDomain($name)) {
            throw new DomainNotFoundException(
                sprintf('Domain "%s" not found', $name),
                1778152632,
            );
        }

        $ownEncoded = $this->keyPair->getPublicKeyEncoded();
        foreach ($publicKeys as $pk) {
            $encodedKey = $pk->getEncoded();
            if ($encodedKey === $ownEncoded) {
                throw new SelfLockoutException(
                    'Cannot remove own public key from domain',
                    1778152624,
                );
            }
            unset($data['domains'][$name]['keys'][$encodedKey]);
        }

        $this->storage->save($data);
    }

    public function extendAll(PublicKey ...$publicKeys): void
    {
        foreach ($this->listDomains() as $name) {
            $this->extendDomain($name, ...$publicKeys);
        }
    }

    public function reduceAll(PublicKey ...$publicKeys): void
    {
        foreach ($this->listDomains() as $name) {
            $this->reduceDomain($name, ...$publicKeys);
        }
    }

    public function listDomains(): array
    {
        return array_keys($this->storage->load()['domains'] ?? []);
    }

    public function addPublicKeys(KeyEntry ...$entries): void
    {
        $data = $this->storage->load();
        $existing = array_column($data['keys'], null, 'publicKeyMultibase');
        $newPublicKeys = [];
        foreach ($entries as $entry) {
            $mb = $entry->publicKey->getMultibase();
            if (!isset($existing[$mb])) {
                $existing[$mb] = $entry->toArray();
                $newPublicKeys[] = $entry->publicKey;
            }
        }
        $data['keys'] = array_values($existing);
        $this->storage->save($data);

        $this->extendAll(...$newPublicKeys);
    }

    public function removePublicKeys(PublicKey ...$publicKeys): void
    {
        $data = $this->storage->load();
        $multibasesToRemove = array_map(
            static fn(PublicKey $pk): string => $pk->getMultibase(),
            $publicKeys
        );
        $data['keys'] = array_values(
            array_filter($data['keys'], fn(array $e) => !in_array($e['publicKeyMultibase'], $multibasesToRemove, true))
        );
        $this->storage->save($data);

        $ownEncoded = $this->keyPair->getPublicKeyEncoded();
        $keysToReduce = array_values(
            array_filter($publicKeys, fn(PublicKey $pk) => $pk->getEncoded() !== $ownEncoded),
        );
        if ($keysToReduce !== []) {
            $this->reduceAll(...$keysToReduce);
        }
    }

    public function listPublicKeys(): array
    {
        return array_map(
            static fn(array $e): KeyEntry => KeyEntry::fromArray($e),
            $this->storage->load()['keys'],
        );
    }

    public function getDataKey(string $domain): string
    {
        $data = $this->storage->load();

        if (!$this->hasDomain($domain)) {
            throw new DomainNotFoundException(
                sprintf('Domain "%s" not found', $domain),
                1778152636,
            );
        }

        return $this->unsealDataKey($data['domains'][$domain], $this->keyPair->getPublicKeyEncoded());
    }

    private function sealDataKey(string $dataKey, PublicKey $publicKey): string
    {
        return sodium_bin2base64(
            sodium_crypto_box_seal($dataKey, $publicKey->getRawBytes()),
            SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
        );
    }

    private function unsealDataKey(array $domainData, string $ownPublicKeyEncoded): string
    {
        $keys = $domainData['keys'] ?? [];

        if (!isset($keys[$ownPublicKeyEncoded])) {
            throw new DecryptionException(
                sprintf('No sealed data key found for public key "%s"', $ownPublicKeyEncoded),
                1778152626,
            );
        }

        try {
            $ciphertext = sodium_base642bin($keys[$ownPublicKeyEncoded], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\SodiumException $e) {
            throw new InvalidKeyMaterialException(
                sprintf('Invalid base64 encoding in sealed data key for public key "%s"', $ownPublicKeyEncoded),
                1778512521,
                $e,
            );
        }
        $dataKey = sodium_crypto_box_seal_open($ciphertext, $this->keyPair->getSodiumKeyPair());

        if ($dataKey === false) {
            throw new DecryptionException(
                'Failed to unseal data key — wrong key or corrupted ciphertext',
                1778152627,
            );
        }

        return $dataKey;
    }
}
