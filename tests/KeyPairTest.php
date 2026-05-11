<?php

declare(strict_types=1);

namespace OliverHader\SecretsKms\Tests;

use OliverHader\SecretsKms\Exception\InvalidKeyMaterialException;
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
        $this->expectException(InvalidKeyMaterialException::class);
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

    public function testSecretKeyFingerprintMatchesPublicKeyFingerprint(): void
    {
        $kp = KeyPair::generate();

        self::assertSame(
            $kp->getPublicKey()->getFingerprint(),
            $kp->getSecretKey()->getFingerprint(),
        );
    }

    public function testSecretKeyFingerprintIsDeterministic(): void
    {
        $a = KeyPair::fromSeed('fingerprint-secret-test');
        $b = KeyPair::fromSeed('fingerprint-secret-test');

        self::assertSame($a->getSecretKey()->getFingerprint(), $b->getSecretKey()->getFingerprint());
    }

    // PublicKey

    public function testPublicKeyFromRawBytesThrowsOnWrongLength(): void
    {
        $this->expectException(InvalidKeyMaterialException::class);
        $this->expectExceptionMessageMatches('/Public key must be \d+ bytes/');
        $this->expectExceptionCode(1778152633);

        PublicKey::fromRawBytes('tooshort');
    }

    public function testPublicKeyFromEncodedThrowsOnInvalidBase64(): void
    {
        $this->expectException(InvalidKeyMaterialException::class);
        $this->expectExceptionMessageMatches('/Invalid base64 encoding for public key/');
        $this->expectExceptionCode(1778512522);

        PublicKey::fromEncoded('!!!not-valid-base64!!!');
    }

    public function testPublicKeyFromEncodedThrowsOnInvalidKey(): void
    {
        $this->expectException(InvalidKeyMaterialException::class);
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

    public function testPublicKeyFingerprintIs43CharUrlSafeBase64(): void
    {
        $fingerprint = KeyPair::generate()->getPublicKey()->getFingerprint();

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $fingerprint);
        self::assertStringNotContainsString('=', $fingerprint);
        self::assertStringNotContainsString('+', $fingerprint);
        self::assertStringNotContainsString('/', $fingerprint);
    }

    public function testPublicKeyFingerprintIsDeterministic(): void
    {
        $a = KeyPair::fromSeed('fingerprint-test');
        $b = KeyPair::fromSeed('fingerprint-test');

        self::assertSame($a->getPublicKey()->getFingerprint(), $b->getPublicKey()->getFingerprint());
    }

    public function testPublicKeyFingerprintDiffersForDifferentKeys(): void
    {
        $a = KeyPair::fromSeed('fingerprint-key-a');
        $b = KeyPair::fromSeed('fingerprint-key-b');

        self::assertNotSame($a->getPublicKey()->getFingerprint(), $b->getPublicKey()->getFingerprint());
    }
}
