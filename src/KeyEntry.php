<?php

declare(strict_types=1);

namespace OliverHader\SecretsKms;

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
