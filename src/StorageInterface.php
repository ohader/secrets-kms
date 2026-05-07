<?php

declare(strict_types=1);

namespace OliverHader\SecretsKms;

interface StorageInterface
{
    public function load(): array;

    public function save(array $data): void;
}
