<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Test\Unit\Model\Util;

use Magento\Framework\Filesystem;
use Magento\Framework\Filesystem\Directory\ReadInterface;
use PHPUnit\Framework\TestCase;
use StackNuts\StackGaugeSecurity\Model\Util\ContentSignatureScanner;
use StackNuts\StackGaugeSecurity\Model\Util\GeneratedCodeScanner;

class GeneratedCodeScannerTest extends TestCase
{
    private string $base;
    private string $root;

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir() . '/sg-generated-' . uniqid();
        $this->root = $this->base;
        mkdir($this->base . '/generated/code/Vendor/Interceptor', 0777, true);
    }

    protected function tearDown(): void
    {
        if (!is_dir($this->base)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->base, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $file) {
            $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        }
        rmdir($this->base);
    }

    private function scanner(): GeneratedCodeScanner
    {
        $read = $this->createStub(ReadInterface::class);
        $read->method('getAbsolutePath')->willReturnCallback(
            fn (string $path): string => $this->root . '/' . $path
        );
        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willReturn($read);

        return new GeneratedCodeScanner($filesystem, new ContentSignatureScanner());
    }

    private function signature(): array
    {
        return [[
            'id' => 'gen-test',
            'name' => 'Test backdoor marker',
            'severity' => 'critical',
            'target' => ['generated_php'],
            'pattern_type' => 'literal',
            'pattern' => 'BACKDOOR_MARKER_XYZ',
        ]];
    }

    public function testMatchesAPhpFileUnderGeneratedCode(): void
    {
        file_put_contents(
            $this->root . '/generated/code/Vendor/Interceptor/Plugin.php',
            '<?php eval($_POST["BACKDOOR_MARKER_XYZ"]);'
        );

        $result = $this->scanner()->scan($this->signature());

        $this->assertCount(1, $result['matches']);
        $this->assertSame('gen-test', $result['matches'][0]['signature_id']);
        $this->assertStringContainsString('Interceptor/Plugin.php', $result['matches'][0]['location']);
        $this->assertFalse($result['truncated']);
    }

    public function testIgnoresNonPhpFiles(): void
    {
        file_put_contents($this->root . '/generated/code/Vendor/Interceptor/notes.txt', 'BACKDOOR_MARKER_XYZ');

        $this->assertSame([], $this->scanner()->scan($this->signature())['matches']);
    }

    public function testReturnsNothingWhenGeneratedCodeIsAbsent(): void
    {
        $this->root = $this->base . '/does-not-exist';

        $this->assertSame(
            ['matches' => [], 'truncated' => false],
            $this->scanner()->scan($this->signature())
        );
    }
}
