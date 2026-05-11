<?php

declare(strict_types=1);

namespace OliverHader\SecretsKms\Tests;

use OliverHader\SecretsKms\Exception\StorageException;
use OliverHader\SecretsKms\Storage;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class StorageTest extends TestCase
{
    private string $tempFile;

    protected function setUp(): void
    {
        $this->tempFile = sys_get_temp_dir() . '/' . uniqid('secrets_kms_test_', true) . '.json';
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempFile)) {
            unlink($this->tempFile);
        }
    }

    #[Test]
    public function saveAndLoadRoundTrip(): void
    {
        $storage = new Storage($this->tempFile);
        $data = ['domains' => ['typo3/user-settings' => ['keys' => ['abc' => 'xyz']]]];

        $storage->save($data);
        $loaded = $storage->load();

        self::assertSame('xyz', $loaded['domains']['typo3/user-settings']['keys']['abc']);
    }

    #[Test]
    public function loadReturnsEmptyStructureWhenFileDoesNotExist(): void
    {
        $storage = new Storage($this->tempFile . '.nonexistent');
        $loaded = $storage->load();

        self::assertSame(['keys' => [], 'domains' => []], $loaded);
    }

    #[Test]
    public function loadReturnsEmptyStructureForEmptyFile(): void
    {
        file_put_contents($this->tempFile, '');
        $storage = new Storage($this->tempFile);

        self::assertSame(['keys' => [], 'domains' => []], $storage->load());
    }

    #[Test]
    public function loadReturnsEmptyStructureForWhitespaceOnlyFile(): void
    {
        file_put_contents($this->tempFile, "   \n\t  ");
        $storage = new Storage($this->tempFile);

        self::assertSame(['keys' => [], 'domains' => []], $storage->load());
    }

    #[Test]
    public function loadThrowsOnInvalidJson(): void
    {
        file_put_contents($this->tempFile, 'not valid json');
        $storage = new Storage($this->tempFile);

        $this->expectException(StorageException::class);
        $this->expectExceptionMessageMatches('/Invalid JSON/');
        $this->expectExceptionCode(1778152629);

        $storage->load();
    }

    #[Test]
    public function loadThrowsOnUnreadableFile(): void
    {
        file_put_contents($this->tempFile, '{}');
        chmod($this->tempFile, 0000);

        // Only meaningful when not running as root
        if (is_readable($this->tempFile)) {
            $this->markTestSkipped('File is still readable (running as root?)');
        }

        $storage = new Storage($this->tempFile);

        $this->expectException(StorageException::class);
        $this->expectExceptionCode(1778152628);

        $storage->load();
    }

    #[Test]
    public function saveThrowsOnUnwritableDirectory(): void
    {
        $readonlyDir = sys_get_temp_dir() . '/' . uniqid('secrets_kms_ro_', true);
        mkdir($readonlyDir, 0555);

        $storage = new Storage($readonlyDir . '/secrets.json');

        try {
            $this->expectException(StorageException::class);
            $this->expectExceptionCode(1778152630);

            $storage->save(['domains' => []]);
        } finally {
            chmod($readonlyDir, 0755);
            rmdir($readonlyDir);
        }
    }

    #[Test]
    public function loadNormalizesMissingDomainsKey(): void
    {
        file_put_contents($this->tempFile, '{"other": 1}');
        $storage = new Storage($this->tempFile);

        $loaded = $storage->load();

        self::assertArrayHasKey('keys', $loaded);
        self::assertSame([], $loaded['keys']);
        self::assertArrayHasKey('domains', $loaded);
        self::assertSame([], $loaded['domains']);
    }

    #[Test]
    public function savedJsonUsesUnescapedSlashes(): void
    {
        $storage = new Storage($this->tempFile);
        $storage->save(['domains' => ['typo3/user-settings' => ['keys' => []]]]);

        $raw = file_get_contents($this->tempFile);

        self::assertStringContainsString('typo3/user-settings', $raw);
        self::assertStringNotContainsString('typo3\/user-settings', $raw);
    }
}
