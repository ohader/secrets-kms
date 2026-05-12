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

namespace OliverHader\SecretsKms;

use OliverHader\SecretsKms\Exception\InvalidKeyMaterialException;

final class Signer
{
    public function __construct(private readonly Manager $manager) {}

    public function sign(string $domain, string $message): string
    {
        $dataKey = $this->manager->getDataKey($domain);
        $mac = sodium_crypto_auth($message, $dataKey);
        return sodium_bin2base64($mac, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    public function verify(string $domain, string $message, string $mac): bool
    {
        try {
            $rawMac = sodium_base642bin($mac, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\SodiumException $e) {
            throw new InvalidKeyMaterialException('Invalid MAC encoding', 1778512523, $e);
        }

        if (strlen($rawMac) !== SODIUM_CRYPTO_AUTH_BYTES) {
            throw new InvalidKeyMaterialException('MAC has wrong byte length', 1778512524);
        }

        $dataKey = $this->manager->getDataKey($domain);
        return sodium_crypto_auth_verify($rawMac, $message, $dataKey);
    }
}
