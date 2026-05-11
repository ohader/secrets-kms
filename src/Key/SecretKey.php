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

use OliverHader\SecretsKms\Exception\InvalidKeyMaterialException;

final class SecretKey
{
    private function __construct(#[\SensitiveParameter] private readonly string $rawBytes) {}

    public static function fromRawBytes(#[\SensitiveParameter] string $rawBytes): static
    {
        if (strlen($rawBytes) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            throw new InvalidKeyMaterialException(
                sprintf(
                    'Secret key must be %d bytes, got %d',
                    SODIUM_CRYPTO_BOX_SECRETKEYBYTES,
                    strlen($rawBytes),
                ),
                1778152621,
            );
        }
        return new static($rawBytes);
    }

    public function getRawBytes(): string
    {
        return $this->rawBytes;
    }

    public function derivePublicKey(): PublicKey
    {
        return PublicKey::fromRawBytes(
            sodium_crypto_box_publickey_from_secretkey($this->rawBytes),
        );
    }

    public function getFingerprint(): string
    {
        return $this->derivePublicKey()->getFingerprint();
    }
}
