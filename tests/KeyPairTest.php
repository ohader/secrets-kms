<?php

declare(strict_types=1);

namespace OliverHader\SecretsKms\Tests;

use OliverHader\SecretsKms\Exception\RuntimeException;
use OliverHader\SecretsKms\KeyPair;
use OliverHader\SecretsKms\PublicKey;
use OliverHader\SecretsKms\SecretKey;
use PHPUnit\Framework\TestCase;

final class KeyPairTest extends TestCase
{
    public function testGenerateProducesDifferentKeyPairsEachTime(): void
    {
        $a = KeyPair::generate();
        $b = KeyPair::generate();

        self::assertNotSame($a->getPublicKeyEncoded(), $b->getPublicKeyEncoded());
    }

    public function testFromSeedIsDeterministic(): void
    {
        $a = KeyPair::fromSeed('test-secret');
        $b = KeyPair::fromSeed('test-secret');

        self::assertSame($a->getPublicKeyEncoded(), $b->getPublicKeyEncoded());
        self::assertSame($a->getSodiumKeyPair(), $b->getSodiumKeyPair());
    }

    public function testFromSeedDifferentInputsProduceDifferentKeys(): void
    {
        $a = KeyPair::fromSeed('secret-a');
        $b = KeyPair::fromSeed('secret-b');

        self::assertNotSame($a->getPublicKeyEncoded(), $b->getPublicKeyEncoded());
    }

    public function testFromSeedHandlesArbitraryLengthInput(): void
    {
        self::assertNotEmpty(KeyPair::fromSeed('x')->getPublicKeyEncoded());
        self::assertNotEmpty(KeyPair::fromSeed(str_repeat('a', 200))->getPublicKeyEncoded());
    }

    public function testFromSecretKeyRoundTrip(): void
    {
        $original = KeyPair::generate();
        $restored = KeyPair::fromSecretKey($original->getSecretKey());

        self::assertSame($original->getPublicKeyEncoded(), $restored->getPublicKeyEncoded());
    }

    public function testGetSodiumKeyPairHasCorrectLength(): void
    {
        $kp = KeyPair::generate();

        self::assertSame(SODIUM_CRYPTO_BOX_KEYPAIRBYTES, strlen($kp->getSodiumKeyPair()));
    }

    public function testGetPublicKeyEncodedIsUrlSafeBase64WithNoPadding(): void
    {
        $kp = KeyPair::generate();
        $encoded = $kp->getPublicKeyEncoded();

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $encoded);
        self::assertStringNotContainsString('=', $encoded);
        self::assertStringNotContainsString('+', $encoded);
        self::assertStringNotContainsString('/', $encoded);
    }

    public function testSealOpenRoundTripValidatesSodiumKeyPairLayout(): void
    {
        $kp = KeyPair::generate();
        $plaintext = 'hello world';

        $sealed = sodium_crypto_box_seal($plaintext, $kp->getPublicKey()->getRawBytes());
        $opened = sodium_crypto_box_seal_open($sealed, $kp->getSodiumKeyPair());

        self::assertSame($plaintext, $opened);
    }

    // SecretKey

    public function testSecretKeyFromRawBytesThrowsOnWrongLength(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/Secret key must be \d+ bytes/');
        $this->expectExceptionCode(1778152621);

        SecretKey::fromRawBytes('tooshort');
    }

    public function testSecretKeyDerivePublicKeyMatchesKeyPair(): void
    {
        $kp = KeyPair::generate();
        $derived = $kp->getSecretKey()->derivePublicKey();

        self::assertSame($kp->getPublicKeyEncoded(), $derived->getEncoded());
    }

    // PublicKey

    public function testPublicKeyFromRawBytesThrowsOnWrongLength(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/Public key must be \d+ bytes/');
        $this->expectExceptionCode(1778152633);

        PublicKey::fromRawBytes('tooshort');
    }

    public function testPublicKeyFromEncodedThrowsOnInvalidKey(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/Invalid public key/');
        $this->expectExceptionCode(1778152625);

        PublicKey::fromEncoded('bm90YXZhbGlka2V5');
    }

    public function testPublicKeyEncodedRoundTrip(): void
    {
        $kp = KeyPair::generate();
        $encoded = $kp->getPublicKeyEncoded();
        $pk = PublicKey::fromEncoded($encoded);

        self::assertSame($encoded, $pk->getEncoded());
        self::assertSame($kp->getPublicKey()->getRawBytes(), $pk->getRawBytes());
    }
}
