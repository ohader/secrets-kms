<?php

declare(strict_types=1);

namespace OliverHader\SecretsKms;

use OliverHader\SecretsKms\Exception\StorageException;

final class Storage implements StorageInterface
{
    public function __construct(private readonly string $filePath) {}

    public function load(): array
    {
        if (!file_exists($this->filePath)) {
            return ['keys' => [], 'domains' => []];
        }

        $raw = @file_get_contents($this->filePath);
        if ($raw === false) {
            throw new StorageException(
                sprintf('Unable to read file "%s"', $this->filePath),
                1778152628
            );
        }

        if (trim($raw) === '') {
            return ['keys' => [], 'domains' => []];
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

        if (!isset($decoded['keys']) || !is_array($decoded['keys'])) {
            $decoded['keys'] = [];
        }

        if (!isset($decoded['domains']) || !is_array($decoded['domains'])) {
            $decoded['domains'] = [];
        }

        return $decoded;
    }

    public function save(array $data): void
    {
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        if (@file_put_contents($this->filePath, $json) === false) {
            throw new StorageException(
                sprintf('Unable to write file "%s"', $this->filePath),
                1778152630
            );
        }
    }
}
