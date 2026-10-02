<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Test\Unit\Model\Util;

use Magento\Framework\Filesystem;
use Magento\Framework\Filesystem\Directory\ReadInterface;
use Magento\Framework\Module\Dir;
use Magento\Framework\Serialize\Serializer\Json;
use PHPUnit\Framework\TestCase;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureStore;

class SignatureStoreTest extends TestCase
{
    private function storeReturning(?string $contents): SignatureStore
    {
        $dir = $this->createStub(ReadInterface::class);
        $dir->method('isExist')->willReturn($contents !== null);
        $dir->method('readFile')->willReturn($contents ?? '');

        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryReadByPath')->willReturn($dir);

        $moduleDir = $this->createStub(Dir::class);
        $moduleDir->method('getDir')->willReturn('/app/code/StackNuts/StackGaugeSecurity/etc');

        return new SignatureStore($filesystem, $moduleDir, new Json());
    }

    public function testGetSignaturesReturnsEmptyListWhenFileIsMissing(): void
    {
        $this->assertSame([], $this->storeReturning(null)->getSignatures());
    }

    public function testGetSignaturesReturnsEmptyListOnMalformedJson(): void
    {
        $this->assertSame([], $this->storeReturning('not json')->getSignatures());
    }

    public function testGetSignaturesReturnsEmptyListWhenSignaturesKeyIsMissing(): void
    {
        $this->assertSame([], $this->storeReturning(json_encode(['version' => '1.0']))->getSignatures());
    }

    public function testGetSignaturesReturnsTheDecodedList(): void
    {
        $store = $this->storeReturning(json_encode([
            'version' => '2026.10.0',
            'signatures' => [
                ['id' => 'test-1', 'target' => ['pub_php'], 'pattern_type' => 'literal', 'pattern' => 'foo'],
            ],
        ]));

        $this->assertSame(
            [['id' => 'test-1', 'target' => ['pub_php'], 'pattern_type' => 'literal', 'pattern' => 'foo']],
            $store->getSignatures()
        );
    }

    public function testGetVersionReturnsNullWhenFileIsMissing(): void
    {
        $this->assertNull($this->storeReturning(null)->getVersion());
    }

    public function testGetVersionReturnsNullOnMalformedJson(): void
    {
        $this->assertNull($this->storeReturning('not json')->getVersion());
    }

    public function testGetVersionReturnsTheVersionString(): void
    {
        $store = $this->storeReturning(json_encode(['version' => '2026.10.0', 'signatures' => []]));

        $this->assertSame('2026.10.0', $store->getVersion());
    }
}
