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

use OliverHader\SecretsKms\Exception\DomainNotFoundException;
use OliverHader\SecretsKms\Exception\InvalidKeyMaterialException;
use OliverHader\SecretsKms\Key\KeyPair;
use OliverHader\SecretsKms\Manager;
use OliverHader\SecretsKms\Signer;
use OliverHader\SecretsKms\Storage;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class SignerTest extends TestCase
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

    #[Test]
    public function signAndVerifyRoundTrip(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');

        $signer = new Signer($service);
        $mac = $signer->sign('typo3/user-settings', 'hello world');

        self::assertTrue($signer->verify('typo3/user-settings', 'hello world', $mac));
    }

    #[Test]
    public function signProducesDeterministicMac(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');

        $signer = new Signer($service);
        $a = $signer->sign('typo3/user-settings', 'same message');
        $b = $signer->sign('typo3/user-settings', 'same message');

        self::assertSame($a, $b);
    }

    #[Test]
    public function signedOutputIsUrlSafeBase64NoPadding(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');

        $mac = (new Signer($service))->sign('typo3/user-settings', 'hello');

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $mac);
        self::assertStringNotContainsString('=', $mac);
    }

    #[Test]
    public function verifyReturnsFalseOnTamperedMac(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');

        $signer = new Signer($service);
        $mac = $signer->sign('typo3/user-settings', 'message');

        $raw = sodium_base642bin($mac, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        $raw[0] = chr(ord($raw[0]) ^ 0x01);
        $tampered = sodium_bin2base64($raw, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);

        self::assertFalse($signer->verify('typo3/user-settings', 'message', $tampered));
    }

    #[Test]
    public function verifyReturnsFalseOnMessageMismatch(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');

        $signer = new Signer($service);
        $mac = $signer->sign('typo3/user-settings', 'original message');

        self::assertFalse($signer->verify('typo3/user-settings', 'different message', $mac));
    }

    #[Test]
    public function verifyReturnsFalseOnDomainMismatch(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');
        $service->createDomain('typo3/registry-data');

        $signer = new Signer($service);
        $mac = $signer->sign('typo3/user-settings', 'message');

        self::assertFalse($signer->verify('typo3/registry-data', 'message', $mac));
    }

    #[Test]
    public function verifyThrowsOnInvalidBase64(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');

        $this->expectException(InvalidKeyMaterialException::class);
        $this->expectExceptionCode(1778512523);

        (new Signer($service))->verify('typo3/user-settings', 'message', '!!!not-valid-base64!!!');
    }

    #[Test]
    public function verifyThrowsOnWrongMacLength(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');

        $this->expectException(InvalidKeyMaterialException::class);
        $this->expectExceptionCode(1778512524);

        $tooShort = sodium_bin2base64('tooshort', SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        (new Signer($service))->verify('typo3/user-settings', 'message', $tooShort);
    }

    #[Test]
    public function signThrowsDomainNotFoundExceptionOnMissingDomain(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);

        $this->expectException(DomainNotFoundException::class);

        (new Signer($service))->sign('does-not-exist', 'message');
    }

    #[Test]
    public function verifyThrowsDomainNotFoundExceptionOnMissingDomain(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);

        $this->expectException(DomainNotFoundException::class);

        $validMac = sodium_bin2base64(str_repeat("\x00", SODIUM_CRYPTO_AUTH_BYTES), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        (new Signer($service))->verify('does-not-exist', 'message', $validMac);
    }

    #[Test]
    public function multiSystemBothCanVerifyTheSameMac(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $keyB = KeyPair::fromSeed('system-b');

        $serviceA = new Manager($keyA, $this->storage);
        $serviceA->createDomain('typo3/user-settings');
        $serviceA->extendDomain('typo3/user-settings', $keyB->getPublicKey());

        $serviceB = new Manager($keyB, $this->storage);

        $mac = (new Signer($serviceA))->sign('typo3/user-settings', 'shared message');

        self::assertTrue((new Signer($serviceB))->verify('typo3/user-settings', 'shared message', $mac));
    }

    #[Test]
    public function signWorksWithEmptyMessage(): void
    {
        $service = new Manager(KeyPair::fromSeed('system-a'), $this->storage);
        $service->createDomain('typo3/user-settings');

        $signer = new Signer($service);
        $mac = $signer->sign('typo3/user-settings', '');

        self::assertTrue($signer->verify('typo3/user-settings', '', $mac));
    }
}
