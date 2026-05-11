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

use OliverHader\SecretsKms\Exception\StorageException;
use OliverHader\SecretsKms\Model\Domain;
use OliverHader\SecretsKms\Model\KeyEntry;
use OliverHader\SecretsKms\Model\SecretsData;

final class Storage implements StorageInterface
{
    public function __construct(private readonly string $filePath) {}

    public function load(): SecretsData
    {
        if (!file_exists($this->filePath)) {
            return new SecretsData();
        }

        $raw = @file_get_contents($this->filePath);
        if ($raw === false) {
            throw new StorageException(
                sprintf('Unable to read file "%s"', $this->filePath),
                1778152628
            );
        }

        if (trim($raw) === '') {
            return new SecretsData();
        }

        $decoded = json_decode($raw, true);
        if ($decoded === null) {
            throw new StorageException(
                sprintf(
                    'Invalid JSON in secrets file "%s": %s',
                    $this->filePath,
                    json_last_error_msg(),
                ),
                1778152629
            );
        }

        $keys = is_array($decoded['keys'] ?? null) ? $decoded['keys'] : [];
        $domains = is_array($decoded['domains'] ?? null) ? $decoded['domains'] : [];

        return new SecretsData(
            array_map(KeyEntry::fromArray(...), $keys),
            array_map(
                fn(array $d): Domain => new Domain($d['keys'] ?? []),
                $domains,
            ),
        );
    }

    public function save(SecretsData $data): void
    {
        $raw = [
            'keys' => array_map(fn(KeyEntry $e): array => $e->toArray(), $data->keys),
            'domains' => array_map(
                fn(Domain $d): array => ['keys' => $d->keys],
                $data->domains,
            ),
        ];
        $json = json_encode($raw, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        if (@file_put_contents($this->filePath, $json) === false) {
            throw new StorageException(
                sprintf('Unable to write file "%s"', $this->filePath),
                1778152630
            );
        }
    }
}
