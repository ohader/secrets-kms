<?php

declare(strict_types=1);

namespace OliverHader\SecretsKms\Model;

final class Domain
{
    /** @param array<string, string> $keys Encoded public key → base64url sealed data key */
    public function __construct(
        public readonly array $keys = [],
    ) {}
}
