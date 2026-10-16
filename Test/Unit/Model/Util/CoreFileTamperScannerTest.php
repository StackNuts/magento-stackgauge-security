<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Test\Unit\Model\Util;

use Magento\Framework\Filesystem;
use Magento\Framework\Filesystem\Directory\ReadInterface;
use Magento\Framework\Serialize\Serializer\Json;
use PHPUnit\Framework\TestCase;
use StackNuts\StackGaugeSecurity\Model\Util\BoundedDirectoryWalker;
use StackNuts\StackGaugeSecurity\Model\Util\ComposerPatchedFiles;
use StackNuts\StackGaugeSecurity\Model\Util\CoreFileTamperScanner;
use StackNuts\StackGaugeSecurity\Model\Util\SafeFileReader;

/**
 * Exercises CoreFileTamperScanner against a real temporary vendor/-shaped directory tree, not
 * mocks - mtime comparisons are genuine filesystem behavior a mock can't stand in for
 * meaningfully.
 */
class CoreFileTamperScannerTest extends TestCase
{
    /**
     * @var string
     */
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/stackgauge_tamper_scanner_test_' . uniqid('', true);
        mkdir($this->root . '/vendor/magento', 0777, true);
        mkdir($this->root . '/vendor/mage-os', 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->root);
    }

    private function removeDirectory(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }

        foreach (scandir($path) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $entryPath = $path . '/' . $entry;
            if (is_link($entryPath)) {
                unlink($entryPath);
            } elseif (is_dir($entryPath)) {
                $this->removeDirectory($entryPath);
            } else {
                unlink($entryPath);
            }
        }

        rmdir($path);
    }

    /**
     * @param string $path
     * @param int $mtime Unix timestamp
     */
    private function writeFileAt(string $path, int $mtime): void
    {
        $directory = dirname($path);
        if (!is_dir($directory)) {
            mkdir($directory, 0777, true);
        }

        file_put_contents($path, '<?php /* test fixture */');
        touch($path, $mtime);
    }

    private function scanner(): CoreFileTamperScanner
    {
        $rootDir = $this->createStub(ReadInterface::class);
        $rootDir->method('getAbsolutePath')->willReturnCallback(
            fn (string $path) => $this->root . '/' . $path
        );
        $rootDir->method('isExist')->willReturnCallback(fn (string $p): bool => file_exists($this->root . '/' . $p));
        $rootDir->method('isFile')->willReturnCallback(fn (string $p): bool => is_file($this->root . '/' . $p));
        $rootDir->method('stat')->willReturnCallback(fn (string $p): array => ['size' => (int)filesize($this->root . '/' . $p)]);
        $rootDir->method('readFile')->willReturnCallback(
            fn (string $p): string => (string)file_get_contents($this->root . '/' . $p)
        );

        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willReturn($rootDir);
        $reader = new SafeFileReader(new Json());

        return new CoreFileTamperScanner(
            $filesystem,
            $reader,
            new BoundedDirectoryWalker(),
            new ComposerPatchedFiles($filesystem, $reader)
        );
    }

    public function testFlagsAFileThatDriftsFarNewerThanItsPackageSiblings(): void
    {
        $now = time();
        $package = $this->root . '/vendor/magento/module-catalog';

        // Five sibling files all written around the same time...
        for ($i = 1; $i <= 5; $i++) {
            $this->writeFileAt("{$package}/Model/File{$i}.php", $now - 86400 * 30);
        }
        // ...and one file touched 5 days after the rest - well past the 48h drift threshold.
        $this->writeFileAt("{$package}/Model/Tampered.php", $now - 86400 * 25);

        $matches = $this->scanner()->scan();

        $this->assertCount(1, $matches);
        $this->assertSame('magento/module-catalog', $matches[0]['package']);
        $this->assertSame('Model/Tampered.php', $matches[0]['path']);
        $this->assertGreaterThanOrEqual(48, $matches[0]['drift_hours']);
    }

    public function testDoesNotFlagFilesWrittenAroundTheSameTime(): void
    {
        $now = time();
        $package = $this->root . '/vendor/mage-os/module-customer';

        for ($i = 1; $i <= 5; $i++) {
            // A few minutes of natural spread during a real composer install/extraction.
            $this->writeFileAt("{$package}/Model/File{$i}.php", $now - ($i * 10));
        }

        $this->assertSame([], $this->scanner()->scan());
    }

    public function testIgnoresNonPhpFiles(): void
    {
        $now = time();
        $package = $this->root . '/vendor/magento/module-catalog';

        for ($i = 1; $i <= 3; $i++) {
            $this->writeFileAt("{$package}/Model/File{$i}.php", $now - 86400 * 30);
        }
        // A README touched far more recently than the PHP siblings - not PHP, must not be flagged.
        touch($package . '/README.md', $now);

        $this->assertSame([], $this->scanner()->scan());
    }

    public function testDoesNotFlagAPackageWithFewerThanTwoFiles(): void
    {
        $now = time();
        $this->writeFileAt($this->root . '/vendor/magento/module-solo/Model/Only.php', $now);

        $this->assertSame([], $this->scanner()->scan());
    }

    public function testNeverFollowsASymlinkedPackageDirectory(): void
    {
        $outside = $this->root . '/outside_vendor';
        $this->writeFileAt($outside . '/Evil.php', time());
        symlink($outside, $this->root . '/vendor/magento/linked-package');

        $this->assertSame([], $this->scanner()->scan());
    }

    public function testIgnoresNonMagentoVendorPrefixes(): void
    {
        $now = time();
        mkdir($this->root . '/vendor/some-other-vendor/package', 0777, true);
        for ($i = 1; $i <= 5; $i++) {
            $this->writeFileAt(
                $this->root . "/vendor/some-other-vendor/package/File{$i}.php",
                $now - 86400 * ($i === 5 ? 1 : 30)
            );
        }

        $this->assertSame([], $this->scanner()->scan());
    }

    public function testChecksPhtmlAndJsFilesToo(): void
    {
        $now = time();
        $package = $this->root . '/vendor/magento/module-checkout';
        for ($i = 1; $i <= 4; $i++) {
            $this->writeFileAt("{$package}/view/File{$i}.php", $now - 86400 * 30);
        }
        $this->writeFileAt("{$package}/view/frontend/templates/skimmer.phtml", $now - 86400 * 20);
        $this->writeFileAt("{$package}/view/frontend/web/js/skimmer.js", $now - 86400 * 20);

        $paths = array_column($this->scanner()->scan(), 'path');
        sort($paths);

        $this->assertSame(['view/frontend/templates/skimmer.phtml', 'view/frontend/web/js/skimmer.js'], $paths);
    }

    public function testExcludesFilesTouchedByAComposerPatch(): void
    {
        $now = time();
        $package = $this->root . '/vendor/magento/module-catalog';
        for ($i = 1; $i <= 5; $i++) {
            $this->writeFileAt("{$package}/Model/File{$i}.php", $now - 86400 * 30);
        }
        $this->writeFileAt("{$package}/Model/Patched.php", $now - 86400 * 10);
        $this->writeFileAt("{$package}/Model/Tampered.php", $now - 86400 * 10);

        mkdir($this->root . '/patches', 0777, true);
        file_put_contents($this->root . '/patches/fix.patch', "--- a/Model/Patched.php\n+++ b/Model/Patched.php\n@@ -1 +1 @@\n-a\n+b\n");
        file_put_contents($this->root . '/composer.json', json_encode([
            'extra' => ['patches' => ['magento/module-catalog' => ['Fix' => 'patches/fix.patch']]],
        ]));

        $paths = array_column($this->scanner()->scan(), 'path');

        $this->assertSame(['Model/Tampered.php'], $paths);
    }
}
