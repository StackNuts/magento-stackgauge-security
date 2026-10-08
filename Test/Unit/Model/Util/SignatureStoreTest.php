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
use StackNuts\StackGaugeSecurity\Model\Util\SafeFileReader;
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
     * @param string|null $feedStatus Contents of the var/ feed-status file, or null for "absent".
     */
    private function store(?string $cache, ?string $bundled, ?string $feedStatus = null): SignatureStore
    {
        $varDir = $this->createStub(ReadInterface::class);
        $varDir->method('isExist')->willReturnCallback(
            static fn (string $path): bool => str_ends_with($path, 'feed_status.json') ? $feedStatus !== null : $cache !== null
        );
        $varDir->method('readFile')->willReturnCallback(
            static fn (string $path): string => str_ends_with($path, 'feed_status.json') ? ($feedStatus ?? '') : ($cache ?? '')
        );

        $etcDir = $this->createStub(ReadInterface::class);
        $etcDir->method('isExist')->willReturn($bundled !== null);
        $etcDir->method('readFile')->willReturn($bundled ?? '');

        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willReturn($varDir);
        $filesystem->method('getDirectoryReadByPath')->willReturn($etcDir);

        $moduleDir = $this->createStub(Dir::class);
        $moduleDir->method('getDir')->willReturn('/app/code/StackNuts/StackGaugeSecurity/etc');

        return new SignatureStore($filesystem, $moduleDir, new SafeFileReader(new Json()), new SignatureSetValidator());
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

    public function testReportsFeedAsTheSourceWhenTheCacheIsActive(): void
    {
        $store = $this->store($this->set('2026.11.0', 'from-cache'), $this->set('2026.10.0', 'bundled'));

        $this->assertSame(SignatureStore::SOURCE_FEED, $store->getSource());
    }

    public function testReportsBundledAsTheSourceWhenFallenBack(): void
    {
        $store = $this->store(null, $this->set('2026.10.0', 'bundled'));

        $this->assertSame(SignatureStore::SOURCE_BUNDLED, $store->getSource());
    }

    public function testReportsNoneAsTheSourceWhenNeitherIsUsable(): void
    {
        $store = $this->store(null, null);

        $this->assertSame(SignatureStore::SOURCE_NONE, $store->getSource());
    }

    public function testReturnsNullLastFeedFetchWhenTheFeedHasNeverBeenFetched(): void
    {
        $store = $this->store(null, $this->set('2026.10.0', 'bundled'), feedStatus: null);

        $this->assertNull($store->getLastFeedFetch());
    }

    public function testReturnsTheLastFeedFetchStatus(): void
    {
        $status = json_encode([
            'attempted_at' => '2026-10-08T14:00:00Z',
            'status' => 'failure',
            'message' => 'signature feed checksum mismatch',
            'ref' => 'main',
        ]);

        $store = $this->store(null, $this->set('2026.10.0', 'bundled'), feedStatus: $status);

        $this->assertSame([
            'attempted_at' => '2026-10-08T14:00:00Z',
            'status' => 'failure',
            'message' => 'signature feed checksum mismatch',
            'ref' => 'main',
        ], $store->getLastFeedFetch());
    }
}
