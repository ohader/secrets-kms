<?php

declare(strict_types=1);

namespace OliverHader\SecretsKms;

use OliverHader\SecretsKms\Model\SecretsData;

interface StorageInterface
{
    public function load(): SecretsData;

    public function save(SecretsData $data): void;
}
