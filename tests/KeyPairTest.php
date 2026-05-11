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

namespace OliverHader\SecretsKms\Tests;

use OliverHader\SecretsKms\Exception\InvalidKeyMaterialException;
use OliverHader\SecretsKms\Key\KeyPair;
use OliverHader\SecretsKms\Key\PublicKey;
use OliverHader\SecretsKms\Key\SecretKey;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class KeyPairTest extends TestCase
{
    #[Test]
    public function generateProducesDifferentKeyPairsEachTime(): void
    {
        $a = KeyPair::generate();
        $b = KeyPair::generate();

        self::assertNotSame($a->getPublicKeyEncoded(), $b->getPublicKeyEncoded());
    }

    #[Test]
    public function fromSeedIsDeterministic(): void
    {
        $a = KeyPair::fromSeed('test-secret');
        $b = KeyPair::fromSeed('test-secret');

        self::assertSame($a->getPublicKeyEncoded(), $b->getPublicKeyEncoded());
        self::assertSame($a->getSodiumKeyPair(), $b->getSodiumKeyPair());
    }

    #[Test]
    public function fromSeedDifferentInputsProduceDifferentKeys(): void
    {
        $a = KeyPair::fromSeed('secret-a');
        $b = KeyPair::fromSeed('secret-b');

        self::assertNotSame($a->getPublicKeyEncoded(), $b->getPublicKeyEncoded());
    }

    #[Test]
    public function fromSeedHandlesArbitraryLengthInput(): void
    {
        self::assertNotEmpty(KeyPair::fromSeed('x')->getPublicKeyEncoded());
        self::assertNotEmpty(KeyPair::fromSeed(str_repeat('a', 200))->getPublicKeyEncoded());
    }

    #[Test]
    public function fromSecretKeyRoundTrip(): void
    {
        $original = KeyPair::generate();
        $restored = KeyPair::fromSecretKey($original->getSecretKey());

        self::assertSame($original->getPublicKeyEncoded(), $restored->getPublicKeyEncoded());
    }

    #[Test]
    public function getSodiumKeyPairHasCorrectLength(): void
    {
        $kp = KeyPair::generate();

        self::assertSame(SODIUM_CRYPTO_BOX_KEYPAIRBYTES, strlen($kp->getSodiumKeyPair()));
    }

    #[Test]
    public function getPublicKeyEncodedIsUrlSafeBase64WithNoPadding(): void
    {
        $kp = KeyPair::generate();
        $encoded = $kp->getPublicKeyEncoded();

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $encoded);
        self::assertStringNotContainsString('=', $encoded);
        self::assertStringNotContainsString('+', $encoded);
        self::assertStringNotContainsString('/', $encoded);
    }

    #[Test]
    public function sealOpenRoundTripValidatesSodiumKeyPairLayout(): void
    {
        $kp = KeyPair::generate();
        $plaintext = 'hello world';

        $sealed = sodium_crypto_box_seal($plaintext, $kp->getPublicKey()->getRawBytes());
        $opened = sodium_crypto_box_seal_open($sealed, $kp->getSodiumKeyPair());

        self::assertSame($plaintext, $opened);
    }

    // SecretKey

    #[Test]
    public function secretKeyFromRawBytesThrowsOnWrongLength(): void
    {
        $this->expectException(InvalidKeyMaterialException::class);
        $this->expectExceptionMessageMatches('/Secret key must be \d+ bytes/');
        $this->expectExceptionCode(1778152621);

        SecretKey::fromRawBytes('tooshort');
    }

    #[Test]
    public function secretKeyDerivePublicKeyMatchesKeyPair(): void
    {
        $kp = KeyPair::generate();
        $derived = $kp->getSecretKey()->derivePublicKey();

        self::assertSame($kp->getPublicKeyEncoded(), $derived->getEncoded());
    }

    #[Test]
    public function secretKeyFingerprintMatchesPublicKeyFingerprint(): void
    {
        $kp = KeyPair::generate();

        self::assertSame(
            $kp->getPublicKey()->getFingerprint(),
            $kp->getSecretKey()->getFingerprint(),
        );
    }

    #[Test]
    public function secretKeyFingerprintIsDeterministic(): void
    {
        $a = KeyPair::fromSeed('fingerprint-secret-test');
        $b = KeyPair::fromSeed('fingerprint-secret-test');

        self::assertSame($a->getSecretKey()->getFingerprint(), $b->getSecretKey()->getFingerprint());
    }

    // PublicKey

    #[Test]
    public function publicKeyFromRawBytesThrowsOnWrongLength(): void
    {
        $this->expectException(InvalidKeyMaterialException::class);
        $this->expectExceptionMessageMatches('/Public key must be \d+ bytes/');
        $this->expectExceptionCode(1778152633);

        PublicKey::fromRawBytes('tooshort');
    }

    #[Test]
    public function publicKeyFromEncodedThrowsOnInvalidBase64(): void
    {
        $this->expectException(InvalidKeyMaterialException::class);
        $this->expectExceptionMessageMatches('/Invalid base64 encoding for public key/');
        $this->expectExceptionCode(1778512522);

        PublicKey::fromEncoded('!!!not-valid-base64!!!');
    }

    #[Test]
    public function publicKeyFromEncodedThrowsOnInvalidKey(): void
    {
        $this->expectException(InvalidKeyMaterialException::class);
        $this->expectExceptionMessageMatches('/Invalid public key/');
        $this->expectExceptionCode(1778152625);

        PublicKey::fromEncoded('bm90YXZhbGlka2V5');
    }

    #[Test]
    public function publicKeyEncodedRoundTrip(): void
    {
        $kp = KeyPair::generate();
        $encoded = $kp->getPublicKeyEncoded();
        $pk = PublicKey::fromEncoded($encoded);

        self::assertSame($encoded, $pk->getEncoded());
        self::assertSame($kp->getPublicKey()->getRawBytes(), $pk->getRawBytes());
    }

    #[Test]
    public function publicKeyFingerprintIs43CharUrlSafeBase64(): void
    {
        $fingerprint = KeyPair::generate()->getPublicKey()->getFingerprint();

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $fingerprint);
        self::assertStringNotContainsString('=', $fingerprint);
        self::assertStringNotContainsString('+', $fingerprint);
        self::assertStringNotContainsString('/', $fingerprint);
    }

    #[Test]
    public function publicKeyFingerprintIsDeterministic(): void
    {
        $a = KeyPair::fromSeed('fingerprint-test');
        $b = KeyPair::fromSeed('fingerprint-test');

        self::assertSame($a->getPublicKey()->getFingerprint(), $b->getPublicKey()->getFingerprint());
    }

    #[Test]
    public function publicKeyFingerprintDiffersForDifferentKeys(): void
    {
        $a = KeyPair::fromSeed('fingerprint-key-a');
        $b = KeyPair::fromSeed('fingerprint-key-b');

        self::assertNotSame($a->getPublicKey()->getFingerprint(), $b->getPublicKey()->getFingerprint());
    }
}
