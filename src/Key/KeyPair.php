<?php

declare(strict_types=1);

/*
 * This file is part of the TYPO3 project.
 *
 * It is free software; you can redistribute it and/or modify it under the terms
 * of the MIT License (MIT). For the full copyright and license information,
 * please read the LICENSE file that was distributed with this source code.
 *
 * The TYPO3 project - inspiring people to share!
 */

namespace OliverHader\SecretsKms\Key;

final class KeyPair
{
    private function __construct(
        #[\SensitiveParameter]
        private readonly SecretKey $secretKey,
        private readonly PublicKey $publicKey,
    ) {}

    public static function generate(): static
    {
        $combined = sodium_crypto_box_keypair();
        return new static(
            SecretKey::fromRawBytes(sodium_crypto_box_secretkey($combined)),
            PublicKey::fromRawBytes(sodium_crypto_box_publickey($combined)),
        );
    }

    public static function fromSeed(#[\SensitiveParameter] string $seed): static
    {
        $seedBytes = sodium_crypto_generichash(
            $seed,
            '',
            SODIUM_CRYPTO_BOX_SEEDBYTES,
        );
        $combined = sodium_crypto_box_seed_keypair($seedBytes);
        return new static(
            SecretKey::fromRawBytes(sodium_crypto_box_secretkey($combined)),
            PublicKey::fromRawBytes(sodium_crypto_box_publickey($combined)),
        );
    }

    public static function fromSecretKey(#[\SensitiveParameter] SecretKey $secretKey): static
    {
        return new static($secretKey, $secretKey->derivePublicKey());
    }

    public function getPublicKey(): PublicKey
    {
        return $this->publicKey;
    }

    public function getSecretKey(): SecretKey
    {
        return $this->secretKey;
    }

    public function getPublicKeyEncoded(): string
    {
        return $this->publicKey->getEncoded();
    }

    /**
     * Returns the combined 64-byte keypair blob expected by sodium_crypto_box_seal_open().
     * Layout: [32-byte secret key][32-byte public key] — matches sodium_crypto_box_keypair() output.
     */
    public function getSodiumKeyPair(): string
    {
        return $this->secretKey->getRawBytes() . $this->publicKey->getRawBytes();
    }
}
