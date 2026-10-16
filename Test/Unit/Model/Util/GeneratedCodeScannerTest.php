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
use StackNuts\StackGaugeSecurity\Model\Util\ContentSignatureScanner;
use StackNuts\StackGaugeSecurity\Model\Util\GeneratedCodeScanner;
use StackNuts\StackGaugeSecurity\Model\Util\SafeFileReader;

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

        return new GeneratedCodeScanner(
            $filesystem,
            new ContentSignatureScanner(),
            new SafeFileReader(new Json()),
            new BoundedDirectoryWalker()
        );
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

    public function testSkipsTheWalkEntirelyWhenNoSignatureTargetsGeneratedPhp(): void
    {
        file_put_contents($this->root . '/generated/code/Vendor/Interceptor/Plugin.php', '<?php // BACKDOOR_MARKER_XYZ');
        $contentScanner = $this->createMock(ContentSignatureScanner::class);
        $contentScanner->expects($this->never())->method('scan');

        $read = $this->createStub(ReadInterface::class);
        $read->method('getAbsolutePath')->willReturnCallback(fn (string $path): string => $this->root . '/' . $path);
        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willReturn($read);
        $scanner = new GeneratedCodeScanner(
            $filesystem,
            $contentScanner,
            new SafeFileReader(new Json()),
            new BoundedDirectoryWalker()
        );

        $signatures = [array_merge($this->signature()[0], ['target' => ['pub_php', 'cms_content']])];

        $this->assertSame(['matches' => [], 'truncated' => false], $scanner->scan($signatures));
    }

    public function testOnlyRunsSignaturesTargetingGeneratedPhp(): void
    {
        file_put_contents($this->root . '/generated/code/Vendor/Interceptor/Plugin.php', '<?php // BACKDOOR_MARKER_XYZ OTHER_MARKER');
        $other = array_merge($this->signature()[0], ['id' => 'other', 'target' => ['pub_php'], 'pattern' => 'OTHER_MARKER']);

        $result = $this->scanner()->scan([$this->signature()[0], $other]);

        $this->assertSame(['gen-test'], array_column($result['matches'], 'signature_id'));
    }

    public function testScansASymlinkedGeneratedCodeRoot(): void
    {
        $real = $this->base . '/shared-generated';
        mkdir($real . '/Vendor', 0777, true);
        file_put_contents($real . '/Vendor/Plugin.php', '<?php // BACKDOOR_MARKER_XYZ');
        $this->root = $this->base . '/release';
        mkdir($this->root . '/generated', 0777, true);
        symlink($real, $this->root . '/generated/code');

        $result = $this->scanner()->scan($this->signature());

        $this->assertCount(1, $result['matches']);
        $this->assertSame('generated/code/Vendor/Plugin.php', $result['matches'][0]['location']);
    }

    public function testStopsAndReportsTruncatedWhenTheTimeBudgetIsSpent(): void
    {
        file_put_contents($this->root . '/generated/code/Vendor/Interceptor/Plugin.php', '<?php // BACKDOOR_MARKER_XYZ');
        $contentScanner = new ContentSignatureScanner();
        $contentScanner->resetBudget();
        (new \ReflectionProperty($contentScanner, 'budgetStartedAt'))->setValue($contentScanner, microtime(true) - 10000);

        $read = $this->createStub(ReadInterface::class);
        $read->method('getAbsolutePath')->willReturnCallback(fn (string $path): string => $this->root . '/' . $path);
        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willReturn($read);
        $scanner = new GeneratedCodeScanner(
            $filesystem,
            $contentScanner,
            new SafeFileReader(new Json()),
            new BoundedDirectoryWalker()
        );

        $result = $scanner->scan($this->signature());

        $this->assertSame([], $result['matches']);
        $this->assertTrue($result['truncated']);
    }
}
