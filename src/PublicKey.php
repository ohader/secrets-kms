<?php

declare(strict_types=1);

namespace OliverHader\SecretsKms;

use OliverHader\SecretsKms\Exception\InvalidKeyMaterialException;

final class PublicKey
{
    private function __construct(private readonly string $rawBytes) {}

    public static function fromEncoded(string $encoded): static
    {
        try {
            $bytes = sodium_base642bin($encoded, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\SodiumException $e) {
            throw new InvalidKeyMaterialException(
                sprintf('Invalid base64 encoding for public key "%s"', $encoded),
                1778512522,
                $e,
            );
        }
        if (strlen($bytes) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidKeyMaterialException(
                sprintf(
                    'Invalid public key "%s": expected %d bytes, got %d',
                    $encoded,
                    SODIUM_CRYPTO_BOX_PUBLICKEYBYTES,
                    strlen($bytes),
                ),
                1778152625,
            );
        }
        return new static($bytes);
    }

    public static function fromRawBytes(string $rawBytes): static
    {
        if (strlen($rawBytes) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidKeyMaterialException(
                sprintf(
                    'Public key must be %d bytes, got %d',
                    SODIUM_CRYPTO_BOX_PUBLICKEYBYTES,
                    strlen($rawBytes),
                ),
                1778152633,
            );
        }
        return new static($rawBytes);
    }

    public function getRawBytes(): string
    {
        return $this->rawBytes;
    }

    public function getEncoded(): string
    {
        return sodium_bin2base64($this->rawBytes, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    public function getMultibase(): string
    {
        return 'z' . $this->getEncoded();
    }

    public function getFingerprint(): string
    {
        return sodium_bin2base64(
            sodium_crypto_generichash($this->rawBytes, '', SODIUM_CRYPTO_GENERICHASH_BYTES),
            SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
        );
    }
}
