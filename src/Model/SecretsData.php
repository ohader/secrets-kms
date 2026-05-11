<?php

declare(strict_types=1);

namespace OliverHader\SecretsKms\Model;

final class SecretsData
{
    /**
     * @param KeyEntry[]            $keys
     * @param array<string, Domain> $domains
     */
    public function __construct(
        public readonly array $keys = [],
        public readonly array $domains = [],
    ) {}
}
