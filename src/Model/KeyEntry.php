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

namespace OliverHader\SecretsKms\Model;

use OliverHader\SecretsKms\Key\PublicKey;

final class KeyEntry
{
    public function __construct(
        public readonly PublicKey $publicKey,
        public readonly string $comment = '',
        public readonly \DateTimeImmutable $imported = new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
    ) {}

    public function toArray(): array
    {
        return [
            'publicKeyMultibase' => $this->publicKey->getMultibase(),
            'comment' => $this->comment,
            'imported' => $this->imported->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z'),
        ];
    }

    public static function fromArray(array $data): static
    {
        $encoded = substr($data['publicKeyMultibase'], 1);
        return new static(
            PublicKey::fromEncoded($encoded),
            $data['comment'] ?? '',
            new \DateTimeImmutable($data['imported'] ?? 'now'),
        );
    }
}
