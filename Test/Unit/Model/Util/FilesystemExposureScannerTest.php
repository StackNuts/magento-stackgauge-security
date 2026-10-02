<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Test\Unit\Model\Util;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Filesystem;
use Magento\Framework\Filesystem\Directory\ReadInterface;
use PHPUnit\Framework\TestCase;
use StackNuts\StackGaugeSecurity\Model\Util\FilesystemExposureScanner;

class FilesystemExposureScannerTest extends TestCase
{
    /**
     * @param list<string> $entries top-level directory/file names
     * @param list<string> $directories which of $entries are directories, not files
     */
    private function dirStub(array $entries, array $directories = []): ReadInterface
    {
        $dir = $this->createStub(ReadInterface::class);
        $dir->method('read')->willReturn($entries);
        $dir->method('isExist')->willReturnCallback(
            static fn (string $path): bool => in_array($path, $entries, true)
        );
        $dir->method('isDirectory')->willReturnCallback(
            static fn (string $path): bool => in_array($path, $directories, true)
        );

        return $dir;
    }

    private function scanner(ReadInterface $rootDir, ReadInterface $pubDir): FilesystemExposureScanner
    {
        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willReturnMap([
            [DirectoryList::ROOT, $rootDir],
            [DirectoryList::PUB, $pubDir],
        ]);

        return new FilesystemExposureScanner($filesystem);
    }

    public function testReportsNothingOnACleanInstall(): void
    {
        $rootDir = $this->dirStub(['composer.json', 'composer.lock', 'app', 'vendor'], ['app', 'vendor']);
        $pubDir = $this->dirStub(['index.php', 'static', 'media', 'errors'], ['static', 'media', 'errors']);

        $this->assertSame([], $this->scanner($rootDir, $pubDir)->scan());
    }

    public function testDetectsGitDirectoryInPubAsMoreSevereThanInRoot(): void
    {
        $rootDir = $this->dirStub(['.git'], ['.git']);
        $pubDir = $this->dirStub(['index.php', '.git'], ['.git']);

        $findings = $this->scanner($rootDir, $pubDir)->scan();

        $this->assertContains(['location' => 'root', 'type' => 'vcs_directory', 'name' => '.git'], $findings);
        $this->assertContains(['location' => 'pub', 'type' => 'vcs_directory', 'name' => '.git'], $findings);
    }

    public function testDetectsBackupFilesByExtension(): void
    {
        $rootDir = $this->dirStub(['dump_2024.sql', 'notes.txt']);
        $pubDir = $this->dirStub(['index.php']);

        $findings = $this->scanner($rootDir, $pubDir)->scan();

        $this->assertContains(['location' => 'root', 'type' => 'backup_file', 'name' => 'dump_2024.sql'], $findings);
        $this->assertCount(1, $findings);
    }

    public function testDetectsUnrecognizedPhpFilesInPubOnly(): void
    {
        $rootDir = $this->dirStub(['composer.json']);
        $pubDir = $this->dirStub(['index.php', 'cron.php', 'shell.php']);

        $findings = $this->scanner($rootDir, $pubDir)->scan();

        $this->assertSame(
            [['location' => 'pub', 'type' => 'unrecognized_php_file', 'name' => 'shell.php']],
            $findings
        );
    }

    public function testDoesNotFlagKnownMagentoEntrypoints(): void
    {
        $rootDir = $this->dirStub([]);
        $pubDir = $this->dirStub(['index.php', 'cron.php', 'get.php', 'health_check.php', 'static.php']);

        $this->assertSame([], $this->scanner($rootDir, $pubDir)->scan());
    }

    public function testReturnsEmptyOnAnyFilesystemError(): void
    {
        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willThrowException(new \RuntimeException('unreadable'));

        $this->assertSame([], (new FilesystemExposureScanner($filesystem))->scan());
    }
}
