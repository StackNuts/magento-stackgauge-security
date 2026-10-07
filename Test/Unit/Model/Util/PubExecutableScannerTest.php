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
use StackNuts\StackGaugeSecurity\Model\Util\PubExecutableScanner;
use StackNuts\StackGaugeSecurity\Model\Util\SafeFileReader;

/**
 * Exercises PubExecutableScanner against a real temporary directory tree, not mocks - its
 * core safety properties (never following symlinks, pruning cache directories, respecting a
 * max depth) are genuine SPL RecursiveDirectoryIterator behavior that a mock can't stand in
 * for meaningfully.
 */
class PubExecutableScannerTest extends TestCase
{
    /**
     * @var string
     */
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/stackgauge_pub_scanner_test_' . uniqid('', true);
        mkdir($this->root . '/pub/media', 0777, true);
        mkdir($this->root . '/pub/static', 0777, true);
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

    private function scanner(): PubExecutableScanner
    {
        $pubMediaDir = $this->createStub(ReadInterface::class);
        $pubMediaDir->method('getAbsolutePath')->willReturnCallback(
            fn (string $path) => $this->root . '/' . $path
        );

        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willReturn($pubMediaDir);

        return new PubExecutableScanner($filesystem, new SafeFileReader(new Json()), new BoundedDirectoryWalker());
    }

    public function testDetectsAnExecutableFileDroppedInPubMedia(): void
    {
        mkdir($this->root . '/pub/media/wysiwyg', 0777, true);
        file_put_contents($this->root . '/pub/media/wysiwyg/shell.php', '<?php /* test fixture */');

        $matches = $this->scanner()->scan();

        $this->assertCount(1, $matches);
        $this->assertSame('pub/media', $matches[0]['directory']);
        $this->assertSame('wysiwyg/shell.php', $matches[0]['path']);
    }

    public function testIgnoresOrdinaryStaticAssetFiles(): void
    {
        file_put_contents($this->root . '/pub/media/logo.png', 'not really a png, just a fixture');
        file_put_contents($this->root . '/pub/static/app.js', 'console.log("fixture");');

        $this->assertSame([], $this->scanner()->scan());
    }

    public function testPrunesCacheDirectoriesRatherThanScanningThem(): void
    {
        mkdir($this->root . '/pub/media/catalog/product/cache', 0777, true);
        file_put_contents($this->root . '/pub/media/catalog/product/cache/evil.php', '<?php /* test fixture */');

        $this->assertSame([], $this->scanner()->scan());
    }

    public function testNeverFollowsASymlinkedDirectory(): void
    {
        $outside = $this->root . '/outside_webroot';
        mkdir($outside, 0777, true);
        file_put_contents($outside . '/shell.php', '<?php /* test fixture */');
        symlink($outside, $this->root . '/pub/media/linked');

        $this->assertSame([], $this->scanner()->scan());
    }

    public function testRespectsMaxDepth(): void
    {
        $path = $this->root . '/pub/media';
        // 10 levels deep - past the scanner's own MAX_DEPTH (8).
        for ($i = 0; $i < 10; $i++) {
            $path .= '/level' . $i;
        }
        mkdir($path, 0777, true);
        file_put_contents($path . '/deep_shell.php', '<?php /* test fixture */');

        $this->assertSame([], $this->scanner()->scan());
    }

    public function testFindsAFileWellWithinMaxDepth(): void
    {
        $path = $this->root . '/pub/media/a/b/c';
        mkdir($path, 0777, true);
        file_put_contents($path . '/shallow_shell.php', '<?php /* test fixture */');

        $matches = $this->scanner()->scan();

        $this->assertCount(1, $matches);
        $this->assertSame('a/b/c/shallow_shell.php', $matches[0]['path']);
    }

    public function testReturnsEmptyWhenTheDirectoryDoesNotExistAtAll(): void
    {
        $this->removeDirectory($this->root . '/pub/media');
        $this->removeDirectory($this->root . '/pub/static');

        $this->assertSame([], $this->scanner()->scan());
    }
}
