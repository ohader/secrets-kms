<?php

declare(strict_types=1);

namespace OliverHader\SecretsKms\Tests;

use OliverHader\SecretsKms\Exception\DecryptionException;
use OliverHader\SecretsKms\Exception\DomainNotFoundException;
use OliverHader\SecretsKms\Exception\RuntimeException;
use OliverHader\SecretsKms\KeyEntry;
use OliverHader\SecretsKms\KeyPair;
use OliverHader\SecretsKms\Manager;
use OliverHader\SecretsKms\Storage;
use PHPUnit\Framework\TestCase;

final class ManagerTest extends TestCase
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

    public function testCreateDomainStoresDomainWithCreatorsOwnKey(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $manager = new Manager($keyA, $this->storage);

        $manager->createDomain('typo3/user-settings');

        $data = $this->storage->load();
        self::assertArrayHasKey('typo3/user-settings', $data['domains']);
        self::assertArrayHasKey($keyA->getPublicKeyEncoded(), $data['domains']['typo3/user-settings']['keys']);
    }

    public function testCreateDomainThrowsIfAlreadyExists(): void
    {
        $manager = new Manager('system-a', $this->storage);
        $manager->createDomain('typo3/user-settings');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/already exists/');

        $manager->createDomain('typo3/user-settings');
    }

    public function testRemoveDomainDeletesDomain(): void
    {
        $manager = new Manager('system-a', $this->storage);
        $manager->createDomain('typo3/user-settings');
        $manager->removeDomain('typo3/user-settings');

        $data = $this->storage->load();
        self::assertArrayNotHasKey('typo3/user-settings', $data['domains']);
    }

    public function testRemoveDomainThrowsOnMissingDomain(): void
    {
        $manager = new Manager('system-a', $this->storage);

        $this->expectException(DomainNotFoundException::class);

        $manager->removeDomain('does-not-exist');
    }

    public function testListDomainsReturnsAllCreatedDomains(): void
    {
        $manager = new Manager('system-a', $this->storage);
        $manager->createDomain('typo3/user-settings');
        $manager->createDomain('typo3/registry-data');

        $domains = $manager->listDomains();

        self::assertEqualsCanonicalizing(['typo3/user-settings', 'typo3/registry-data'], $domains);
    }

    public function testListDomainsReturnsEmptyArrayWhenNoneExist(): void
    {
        $manager = new Manager('system-a', $this->storage);

        self::assertSame([], $manager->listDomains());
    }

    public function testMultiSystemScenarioBothSystemsCanUnsealTheSameDataKey(): void
    {
        $keyA = KeyPair::fromSeed('production-secret');
        $keyB = KeyPair::fromSeed('dev-secret');

        $managerA = new Manager($keyA, $this->storage);
        $managerA->createDomain('typo3/user-settings');
        $managerA->extendDomain('typo3/user-settings', $keyB->getPublicKey());

        $data = $this->storage->load();
        $keys = $data['domains']['typo3/user-settings']['keys'];

        self::assertArrayHasKey($keyA->getPublicKeyEncoded(), $keys);
        self::assertArrayHasKey($keyB->getPublicKeyEncoded(), $keys);

        $ciphertextA = sodium_base642bin($keys[$keyA->getPublicKeyEncoded()], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        $dataKeyFromA = sodium_crypto_box_seal_open($ciphertextA, $keyA->getSodiumKeyPair());
        self::assertNotFalse($dataKeyFromA, 'System A could not unseal its own data key');

        $ciphertextB = sodium_base642bin($keys[$keyB->getPublicKeyEncoded()], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        $dataKeyFromB = sodium_crypto_box_seal_open($ciphertextB, $keyB->getSodiumKeyPair());
        self::assertNotFalse($dataKeyFromB, 'System B could not unseal its data key');

        self::assertSame($dataKeyFromA, $dataKeyFromB, 'Both systems must recover the same underlying data key');
    }

    public function testExtendDomainThrowsDecryptionExceptionWhenCallerNotMember(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $keyC = KeyPair::fromSeed('system-c');

        $managerA = new Manager($keyA, $this->storage);
        $managerA->createDomain('typo3/user-settings');

        $managerC = new Manager($keyC, $this->storage);

        $this->expectException(DecryptionException::class);

        $managerC->extendDomain('typo3/user-settings');
    }

    public function testExtendDomainThrowsOnMissingDomain(): void
    {
        $manager = new Manager('system-a', $this->storage);

        $this->expectException(DomainNotFoundException::class);

        $manager->extendDomain('does-not-exist');
    }

    public function testExtendDomainIsIdempotentForAlreadyPresentKeys(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $keyB = KeyPair::fromSeed('system-b');
        $managerA = new Manager($keyA, $this->storage);

        $managerA->createDomain('typo3/user-settings', $keyB->getPublicKey());

        $dataBefore = $this->storage->load();
        $sealedBefore = $dataBefore['domains']['typo3/user-settings']['keys'][$keyB->getPublicKeyEncoded()];

        $managerA->extendDomain('typo3/user-settings', $keyB->getPublicKey());

        $dataAfter = $this->storage->load();
        $sealedAfter = $dataAfter['domains']['typo3/user-settings']['keys'][$keyB->getPublicKeyEncoded()];

        self::assertSame($sealedBefore, $sealedAfter);
    }

    public function testReduceDomainRemovesTargetKeyLeavesCallerIntact(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $keyB = KeyPair::fromSeed('system-b');
        $managerA = new Manager($keyA, $this->storage);

        $managerA->createDomain('typo3/user-settings', $keyB->getPublicKey());
        $managerA->reduceDomain('typo3/user-settings', $keyB->getPublicKey());

        $data = $this->storage->load();
        $keys = $data['domains']['typo3/user-settings']['keys'];

        self::assertArrayNotHasKey($keyB->getPublicKeyEncoded(), $keys);
        self::assertArrayHasKey($keyA->getPublicKeyEncoded(), $keys);
    }

    public function testReduceDomainIsIdempotentForAbsentKeys(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $keyB = KeyPair::fromSeed('system-b');
        $managerA = new Manager($keyA, $this->storage);

        $managerA->createDomain('typo3/user-settings');

        // B was never added — removing it should not throw
        $managerA->reduceDomain('typo3/user-settings', $keyB->getPublicKey());

        $data = $this->storage->load();
        self::assertArrayHasKey($keyA->getPublicKeyEncoded(), $data['domains']['typo3/user-settings']['keys']);
    }

    public function testReduceDomainThrowsOnSelfRemoval(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $managerA = new Manager($keyA, $this->storage);
        $managerA->createDomain('typo3/user-settings');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/own public key/');

        $managerA->reduceDomain('typo3/user-settings', $keyA->getPublicKey());
    }

    public function testReduceDomainThrowsOnMissingDomain(): void
    {
        $manager = new Manager('system-a', $this->storage);

        $this->expectException(DomainNotFoundException::class);

        $manager->reduceDomain('does-not-exist');
    }

    public function testExtendAllAppliesAcrossAllDomains(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $keyB = KeyPair::fromSeed('system-b');
        $managerA = new Manager($keyA, $this->storage);

        $managerA->createDomain('typo3/user-settings');
        $managerA->createDomain('typo3/registry-data');

        $managerA->extendAll($keyB->getPublicKey());

        $data = $this->storage->load();
        self::assertArrayHasKey($keyB->getPublicKeyEncoded(), $data['domains']['typo3/user-settings']['keys']);
        self::assertArrayHasKey($keyB->getPublicKeyEncoded(), $data['domains']['typo3/registry-data']['keys']);
    }

    public function testReduceAllAppliesAcrossAllDomains(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $keyB = KeyPair::fromSeed('system-b');
        $managerA = new Manager($keyA, $this->storage);

        $managerA->createDomain('typo3/user-settings', $keyB->getPublicKey());
        $managerA->createDomain('typo3/registry-data', $keyB->getPublicKey());

        $managerA->reduceAll($keyB->getPublicKey());

        $data = $this->storage->load();
        self::assertArrayNotHasKey($keyB->getPublicKeyEncoded(), $data['domains']['typo3/user-settings']['keys']);
        self::assertArrayNotHasKey($keyB->getPublicKeyEncoded(), $data['domains']['typo3/registry-data']['keys']);
    }

    public function testManagerFromStringAndFromKeyPairAreEquivalent(): void
    {
        $seed = 'my-secret';
        $kp = KeyPair::fromSeed($seed);

        $managerFromString = new Manager($seed, $this->storage);
        $managerFromString->createDomain('typo3/user-settings');

        $data = $this->storage->load();
        self::assertArrayHasKey($kp->getPublicKeyEncoded(), $data['domains']['typo3/user-settings']['keys']);
    }

    public function testCreateDomainAcceptsExplicitPublicKeys(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $keyB = KeyPair::fromSeed('system-b');
        $managerA = new Manager($keyA, $this->storage);

        $managerA->createDomain('typo3/user-settings', $keyB->getPublicKey());

        $data = $this->storage->load();
        $keys = $data['domains']['typo3/user-settings']['keys'];

        self::assertArrayHasKey($keyA->getPublicKeyEncoded(), $keys);
        self::assertArrayHasKey($keyB->getPublicKeyEncoded(), $keys);
    }

    public function testAddPublicKeysPersistsKeysAndExtendsAllDomains(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $keyB = KeyPair::fromSeed('system-b');
        $managerA = new Manager($keyA, $this->storage);

        $managerA->createDomain('typo3/user-settings');
        $managerA->createDomain('typo3/registry-data');

        $managerA->addPublicKeys(new KeyEntry($keyB->getPublicKey()));

        $data = $this->storage->load();
        self::assertCount(1, $data['keys']);
        self::assertSame('z' . $keyB->getPublicKeyEncoded(), $data['keys'][0]['publicKeyMultibase']);
        self::assertArrayHasKey($keyB->getPublicKeyEncoded(), $data['domains']['typo3/user-settings']['keys']);
        self::assertArrayHasKey($keyB->getPublicKeyEncoded(), $data['domains']['typo3/registry-data']['keys']);
    }

    public function testAddPublicKeysIsIdempotent(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $keyB = KeyPair::fromSeed('system-b');
        $managerA = new Manager($keyA, $this->storage);

        $managerA->addPublicKeys(new KeyEntry($keyB->getPublicKey()));
        $managerA->addPublicKeys(new KeyEntry($keyB->getPublicKey()));

        $data = $this->storage->load();
        self::assertCount(1, $data['keys']);
        self::assertSame('z' . $keyB->getPublicKeyEncoded(), $data['keys'][0]['publicKeyMultibase']);
    }

    public function testRemovePublicKeysPurgesKeysAndReducesAllDomains(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $keyB = KeyPair::fromSeed('system-b');
        $managerA = new Manager($keyA, $this->storage);

        $managerA->createDomain('typo3/user-settings');
        $managerA->addPublicKeys(new KeyEntry($keyB->getPublicKey()));

        $managerA->removePublicKeys($keyB->getPublicKey());

        $data = $this->storage->load();
        self::assertSame([], $data['keys']);
        self::assertArrayNotHasKey($keyB->getPublicKeyEncoded(), $data['domains']['typo3/user-settings']['keys']);
    }

    public function testRemovePublicKeysSilentlySkipsOwnKey(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $managerA = new Manager($keyA, $this->storage);

        $managerA->createDomain('typo3/user-settings');
        $managerA->addPublicKeys(new KeyEntry($keyA->getPublicKey()));

        // Own key in removePublicKeys must not throw, even though reduceDomain forbids self-removal
        $managerA->removePublicKeys($keyA->getPublicKey());

        $data = $this->storage->load();
        self::assertSame([], $data['keys']);
        // Domain entry for own key must still be intact
        self::assertArrayHasKey($keyA->getPublicKeyEncoded(), $data['domains']['typo3/user-settings']['keys']);
    }

    public function testListPublicKeysReturnsRegisteredKeys(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $keyB = KeyPair::fromSeed('system-b');
        $keyC = KeyPair::fromSeed('system-c');
        $managerA = new Manager($keyA, $this->storage);

        $managerA->addPublicKeys(new KeyEntry($keyB->getPublicKey()), new KeyEntry($keyC->getPublicKey()));

        $result = $managerA->listPublicKeys();
        self::assertCount(2, $result);
        $multibaseValues = array_map(fn(KeyEntry $e) => $e->publicKey->getMultibase(), $result);
        self::assertEqualsCanonicalizing(
            ['z' . $keyB->getPublicKeyEncoded(), 'z' . $keyC->getPublicKeyEncoded()],
            $multibaseValues,
        );
    }

    public function testListPublicKeysReturnsEmptyArrayInitially(): void
    {
        $manager = new Manager('system-a', $this->storage);

        self::assertSame([], $manager->listPublicKeys());
    }

    public function testCreateDomainIncludesAutoPublicKeys(): void
    {
        $keyA = KeyPair::fromSeed('system-a');
        $keyB = KeyPair::fromSeed('system-b');
        $managerA = new Manager($keyA, $this->storage);

        $managerA->addPublicKeys(new KeyEntry($keyB->getPublicKey()));
        // Domain created after addPublicKeys — B should get access automatically
        $managerA->createDomain('typo3/user-settings');

        $data = $this->storage->load();
        $keys = $data['domains']['typo3/user-settings']['keys'];
        self::assertArrayHasKey($keyA->getPublicKeyEncoded(), $keys);
        self::assertArrayHasKey($keyB->getPublicKeyEncoded(), $keys);
    }
}
