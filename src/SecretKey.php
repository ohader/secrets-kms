<?php

declare(strict_types=1);

namespace OliverHader\SecretsKms;

use OliverHader\SecretsKms\Exception\RuntimeException;

final class SecretKey
{
    private function __construct(#[\SensitiveParameter] private readonly string $rawBytes)
    {
    }

    public static function fromRawBytes(#[\SensitiveParameter] string $rawBytes): static
    {
        if (strlen($rawBytes) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            throw new RuntimeException(
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
}
