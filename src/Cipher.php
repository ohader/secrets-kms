<?php

declare(strict_types=1);

namespace OliverHader\SecretsKms;

use OliverHader\SecretsKms\Exception\DecryptionException;
use OliverHader\SecretsKms\Exception\InvalidKeyMaterialException;

final class Cipher
{
    public function __construct(private readonly Manager $manager) {}

    public function sealWithDomainDataKey(string $domain, string $plaintext): string
    {
        $dataKey = $this->manager->getDataKey($domain);
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            $domain,
            $nonce,
            $dataKey,
        );
        return sodium_bin2base64(
            $nonce . $ciphertext,
            SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
        );
    }

    public function unsealWithDomainDataKey(string $domain, string $sealed): string
    {
        $dataKey = $this->manager->getDataKey($domain);

        try {
            $raw = sodium_base642bin($sealed, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\SodiumException $e) {
            throw new InvalidKeyMaterialException('Invalid sealed value encoding', 1778152637, $e);
        }

        $nonceLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

        if (strlen($raw) <= $nonceLen) {
            throw new DecryptionException(
                'Sealed value is too short to contain a nonce',
                1778152634,
            );
        }

        $nonce = substr($raw, 0, $nonceLen);
        $ciphertext = substr($raw, $nonceLen);

        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $ciphertext,
            $domain,
            $nonce,
            $dataKey,
        );

        if ($plaintext === false) {
            throw new DecryptionException(
                'Failed to decrypt sealed value — wrong key, wrong domain, or corrupted data',
                1778152635,
            );
        }

        return $plaintext;
    }
}
