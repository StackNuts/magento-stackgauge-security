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
use StackNuts\StackGaugeSecurity\Model\Util\SignatureSetValidator;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureStore;

class SignatureStoreTest extends TestCase
{
    private function set(string $version, string $id): string
    {
        return json_encode([
            'version' => $version,
            'signatures' => [[
                'id' => $id,
                'name' => 'n',
                'severity' => 'critical',
                'target' => ['pub_php'],
                'pattern_type' => 'literal',
                'pattern' => 'x',
            ]],
        ]);
    }

    /**
     * @param string|null $cache Contents of the var/ cache file, or null for "absent".
     * @param string|null $bundled Contents of the bundled etc/signatures.json, or null for "absent".
     */
    private function store(?string $cache, ?string $bundled): SignatureStore
    {
        $varDir = $this->createStub(ReadInterface::class);
        $varDir->method('isExist')->willReturn($cache !== null);
        $varDir->method('readFile')->willReturn($cache ?? '');

        $etcDir = $this->createStub(ReadInterface::class);
        $etcDir->method('isExist')->willReturn($bundled !== null);
        $etcDir->method('readFile')->willReturn($bundled ?? '');

        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willReturn($varDir);
        $filesystem->method('getDirectoryReadByPath')->willReturn($etcDir);

        $moduleDir = $this->createStub(Dir::class);
        $moduleDir->method('getDir')->willReturn('/app/code/StackNuts/StackGaugeSecurity/etc');

        return new SignatureStore($filesystem, $moduleDir, new Json(), new SignatureSetValidator());
    }

    public function testPrefersAValidCachedFeedOverTheBundledSet(): void
    {
        $store = $this->store($this->set('2026.11.0', 'from-cache'), $this->set('2026.10.0', 'bundled'));

        $this->assertSame('2026.11.0', $store->getVersion());
        $this->assertSame('from-cache', $store->getSignatures()[0]['id']);
    }

    public function testFallsBackToTheBundledSetWhenThereIsNoCache(): void
    {
        $store = $this->store(null, $this->set('2026.10.0', 'bundled'));

        $this->assertSame('2026.10.0', $store->getVersion());
        $this->assertSame('bundled', $store->getSignatures()[0]['id']);
    }

    public function testFallsBackToTheBundledSetWhenTheCacheIsCorrupt(): void
    {
        $store = $this->store('not json at all', $this->set('2026.10.0', 'bundled'));

        $this->assertSame('bundled', $store->getSignatures()[0]['id']);
    }

    public function testFallsBackToTheBundledSetWhenTheCacheFailsValidation(): void
    {
        $invalidCache = '{"signatures":[{"id":"a","name":"n","severity":"urgent","target":["x"],'
            . '"pattern_type":"literal","pattern":"x"}]}';

        $store = $this->store($invalidCache, $this->set('2026.10.0', 'bundled'));

        $this->assertSame('bundled', $store->getSignatures()[0]['id']);
    }

    public function testReturnsAnEmptyListWhenNeitherSourceIsUsable(): void
    {
        $store = $this->store(null, null);

        $this->assertSame([], $store->getSignatures());
        $this->assertNull($store->getVersion());
    }
}
