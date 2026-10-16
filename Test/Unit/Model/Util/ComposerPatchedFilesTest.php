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
use StackNuts\StackGaugeSecurity\Model\Util\ComposerPatchedFiles;
use StackNuts\StackGaugeSecurity\Model\Util\SafeFileReader;

class ComposerPatchedFilesTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/sg-patched-' . uniqid('', true);
        mkdir($this->root . '/patches', 0777, true);
        mkdir($this->root . '/vendor/composer', 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (['/patches/fix.patch', '/composer.json', '/patches.lock.json', '/vendor/composer/installed.json'] as $f) {
            if (is_file($this->root . $f)) {
                unlink($this->root . $f);
            }
        }
        rmdir($this->root . '/patches');
        rmdir($this->root . '/vendor/composer');
        rmdir($this->root . '/vendor');
        rmdir($this->root);
    }

    private function patched(): ComposerPatchedFiles
    {
        $directory = $this->createStub(ReadInterface::class);
        $directory->method('isExist')->willReturnCallback(fn (string $p): bool => file_exists($this->root . '/' . $p));
        $directory->method('isFile')->willReturnCallback(fn (string $p): bool => is_file($this->root . '/' . $p));
        $directory->method('stat')->willReturnCallback(fn (string $p): array => ['size' => filesize($this->root . '/' . $p)]);
        $directory->method('readFile')->willReturnCallback(
            fn (string $p): string => (string)file_get_contents($this->root . '/' . $p)
        );
        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willReturn($directory);

        return new ComposerPatchedFiles($filesystem, new SafeFileReader(new Json()));
    }

    private function writePatch(): void
    {
        file_put_contents($this->root . '/patches/fix.patch', <<<'DIFF'
diff --git a/Model/Foo.php b/Model/Foo.php
--- a/Model/Foo.php
+++ b/Model/Foo.php
@@ -1 +1 @@
-old
+new
--- a/view/frontend/templates/x.phtml
+++ b/view/frontend/templates/x.phtml
@@ -1 +1 @@
-a
+b
--- /dev/null
+++ b/web/js/new.js
DIFF);
    }

    public function testReadsPatchesDeclaredInComposerJson(): void
    {
        $this->writePatch();
        file_put_contents($this->root . '/composer.json', json_encode([
            'extra' => ['patches' => [
                'magento/module-catalog' => ['Fix foo' => 'patches/fix.patch', 'Remote' => 'https://example.com/x.patch'],
            ]],
        ]));

        $patched = $this->patched();

        $this->assertTrue($patched->isPatched('magento/module-catalog', 'Model/Foo.php'));
        $this->assertTrue($patched->isPatched('Magento/Module-Catalog', 'view/frontend/templates/x.phtml'));
        $this->assertTrue($patched->isPatched('magento/module-catalog', 'web/js/new.js'));
        $this->assertFalse($patched->isPatched('magento/module-catalog', 'Model/Other.php'));
        $this->assertFalse($patched->isPatched('magento/framework', 'Model/Foo.php'));
    }

    public function testReadsPatchesLockFileWithDepthAndVaimoStyleEntries(): void
    {
        $this->writePatch();
        file_put_contents($this->root . '/patches.lock.json', json_encode([
            'patches' => ['magento/framework' => [['url' => 'patches/fix.patch', 'depth' => 2]]],
        ]));
        file_put_contents($this->root . '/composer.json', json_encode([
            'extra' => ['patches' => ['magento/module-sales' => ['Fix' => ['source' => 'patches/fix.patch']]]],
        ]));

        $patched = $this->patched();

        $this->assertTrue($patched->isPatched('magento/framework', 'Foo.php'));
        $this->assertFalse($patched->isPatched('magento/framework', 'Model/Foo.php'));
        $this->assertTrue($patched->isPatched('magento/module-sales', 'Model/Foo.php'));
    }

    public function testReadsPatchesAppliedFromInstalledJson(): void
    {
        $this->writePatch();
        file_put_contents($this->root . '/vendor/composer/installed.json', json_encode([
            'packages' => [['name' => 'magento/module-quote', 'extra' => ['patches_applied' => ['Fix' => 'patches/fix.patch']]]],
        ]));

        $this->assertTrue($this->patched()->isPatched('magento/module-quote', 'Model/Foo.php'));
    }

    public function testNothingIsPatchedWithoutAnyPatchConfiguration(): void
    {
        $this->assertFalse($this->patched()->isPatched('magento/module-catalog', 'Model/Foo.php'));
    }

    public function testRefusesPathsEscapingTheProjectRoot(): void
    {
        file_put_contents($this->root . '/composer.json', json_encode([
            'extra' => ['patches' => ['magento/module-catalog' => ['x' => '../../etc/passwd']]],
        ]));

        $this->assertFalse($this->patched()->isPatched('magento/module-catalog', 'root:x:0:0'));
    }
}
