<?php

declare(strict_types=1);

namespace OliverHader\SecretsKms\Tests;

use OliverHader\SecretsKms\Cipher;
use OliverHader\SecretsKms\Exception\DecryptionException;
use OliverHader\SecretsKms\Exception\DomainNotFoundException;
use OliverHader\SecretsKms\KeyPair;
use OliverHader\SecretsKms\Manager;
use OliverHader\SecretsKms\Storage;
use PHPUnit\Framework\TestCase;

final class CipherTest extends TestCase
{
    private string $tempFile;
    private Storage $storage;

    protected function setUp(): void
    {
        $this->tempFile = sys_get_temp_dir() . '/' . uniqid('secrets_kms_test_', true) . '.json';
        $this->storage = new Storage($this->tempFile);
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempFile)) {
            unlink($this->tempFile);
        }
    }

    public function testSealAndUnsealRoundTrip(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');

        $cipher = new Cipher($service);
        $plaintext = 'my secret value';
        $sealed = $cipher->sealWithDomainDataKey('typo3/user-settings', $plaintext);

        self::assertSame($plaintext, $cipher->unsealWithDomainDataKey('typo3/user-settings', $sealed));
    }

    public function testSealProducesDifferentCiphertextsForSamePlaintext(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');

        $cipher = new Cipher($service);
        $a = $cipher->sealWithDomainDataKey('typo3/user-settings', 'same plaintext');
        $b = $cipher->sealWithDomainDataKey('typo3/user-settings', 'same plaintext');

        // Different nonces must produce different ciphertexts
        self::assertNotSame($a, $b);
    }

    public function testSealedOutputIsUrlSafeBase64NoPadding(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');

        $sealed = (new Cipher($service))->sealWithDomainDataKey('typo3/user-settings', 'hello');

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $sealed);
        self::assertStringNotContainsString('=', $sealed);
    }

    public function testUnsealThrowsDecryptionExceptionOnTamperedCiphertext(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');

        $cipher = new Cipher($service);
        $sealed = $cipher->sealWithDomainDataKey('typo3/user-settings', 'secret');

        // Flip a bit in the last decoded byte (always in the authentication tag)
        $raw = sodium_base642bin($sealed, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        $raw[-1] = chr(ord($raw[-1]) ^ 0x01);
        $tampered = sodium_bin2base64($raw, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);

        $this->expectException(DecryptionException::class);

        $cipher->unsealWithDomainDataKey('typo3/user-settings', $tampered);
    }

    public function testUnsealThrowsDecryptionExceptionWhenDomainMismatch(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');
        $service->createDomain('typo3/registry-data');

        $cipher = new Cipher($service);
        // Seal under domain A, try to unseal under domain B — different data keys AND different AD
        $sealed = $cipher->sealWithDomainDataKey('typo3/user-settings', 'secret');

        $this->expectException(DecryptionException::class);

        $cipher->unsealWithDomainDataKey('typo3/registry-data', $sealed);
    }

    public function testUnsealThrowsDecryptionExceptionOnTooShortInput(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');

        $this->expectException(DecryptionException::class);
        $this->expectExceptionCode(1778152634);

        // Encode fewer bytes than the nonce length
        $tooShort = sodium_bin2base64('tooshort', SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        (new Cipher($service))->unsealWithDomainDataKey('typo3/user-settings', $tooShort);
    }

    public function testSealThrowsDomainNotFoundExceptionOnMissingDomain(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);

        $this->expectException(DomainNotFoundException::class);

        (new Cipher($service))->sealWithDomainDataKey('does-not-exist', 'value');
    }

    public function testUnsealThrowsDomainNotFoundExceptionOnMissingDomain(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);

        $this->expectException(DomainNotFoundException::class);

        (new Cipher($service))->unsealWithDomainDataKey('does-not-exist', 'anything');
    }

    public function testMultiSystemBothCanUnsealTheSameCiphertext(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $keyB = KeyPair::fromSeed('system-b');

        $serviceA = new Manager($keyA, $this->storage);
        $serviceA->createDomain('typo3/user-settings');
        $serviceA->extendDomain('typo3/user-settings', $keyB->getPublicKey());

        $serviceB = new Manager($keyB, $this->storage);

        $plaintext = 'shared secret value';
        $sealed = (new Cipher($serviceA))->sealWithDomainDataKey('typo3/user-settings', $plaintext);
        $decrypted = (new Cipher($serviceB))->unsealWithDomainDataKey('typo3/user-settings', $sealed);

        self::assertSame($plaintext, $decrypted);
    }

    public function testSealPreservesEmptyString(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');

        $cipher = new Cipher($service);
        $sealed = $cipher->sealWithDomainDataKey('typo3/user-settings', '');

        self::assertSame('', $cipher->unsealWithDomainDataKey('typo3/user-settings', $sealed));
    }

    public function testSealPreservesBinaryData(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');

        $cipher = new Cipher($service);
        $binary = random_bytes(256);
        $sealed = $cipher->sealWithDomainDataKey('typo3/user-settings', $binary);

        self::assertSame($binary, $cipher->unsealWithDomainDataKey('typo3/user-settings', $sealed));
    }
}
