<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Test\Unit\Model\Util;

use Magento\Framework\Filesystem;
use Magento\Framework\Filesystem\Directory\WriteInterface;
use Magento\Framework\HTTP\Client\Curl;
use Magento\Framework\Serialize\Serializer\Json;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureFeedFetcher;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureSetValidator;

class SignatureFeedFetcherTest extends TestCase
{
    private const VALID_FEED = '{"version":"2026.10.0","signatures":[{"id":"a","name":"A","severity":"critical",'
        . '"target":["pub_php"],"pattern_type":"literal","pattern":"marker"}]}';

    /**
     * @param array<string, array{0: int, 1: string}> $responses Keyed by the URL's filename,
     *     e.g. "signatures.json", mapped to [http status, body].
     */
    private function fetcher(array $responses, WriteInterface $write, ?LoggerInterface $logger = null): SignatureFeedFetcher
    {
        $current = '';
        $curl = $this->createStub(Curl::class);
        $curl->method('get')->willReturnCallback(static function (string $url) use (&$current): void {
            $current = basename($url);
        });
        $curl->method('getStatus')->willReturnCallback(
            static function () use (&$current, $responses): int {
                return $responses[$current][0] ?? 404;
            }
        );
        $curl->method('getBody')->willReturnCallback(
            static function () use (&$current, $responses): string {
                return $responses[$current][1] ?? '';
            }
        );

        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryWrite')->willReturn($write);

        return new SignatureFeedFetcher(
            $curl,
            $filesystem,
            new SignatureSetValidator(),
            new Json(),
            $logger ?? $this->createStub(LoggerInterface::class)
        );
    }

    private function writeMock(): WriteInterface
    {
        return $this->createMock(WriteInterface::class);
    }

    public function testCachesTheFeedWhenChecksumAndValidationPass(): void
    {
        $checksum = hash('sha256', self::VALID_FEED) . "  signatures.json\n";
        $write = $this->writeMock();
        $write->expects($this->once())->method('writeFile');
        $write->expects($this->once())->method('renameFile');

        $fetcher = $this->fetcher([
            'signatures.json' => [200, self::VALID_FEED],
            'signatures.json.sha256' => [200, $checksum],
        ], $write);

        $this->assertTrue($fetcher->refresh());
    }

    public function testKeepsTheCacheWhenTheChecksumDoesNotMatch(): void
    {
        $write = $this->writeMock();
        $write->expects($this->never())->method('writeFile');

        $fetcher = $this->fetcher([
            'signatures.json' => [200, self::VALID_FEED],
            'signatures.json.sha256' => [200, str_repeat('0', 64) . "  signatures.json\n"],
        ], $write);

        $this->assertFalse($fetcher->refresh());
    }

    public function testKeepsTheCacheWhenTheFeedCannotBeDownloaded(): void
    {
        $write = $this->writeMock();
        $write->expects($this->never())->method('writeFile');

        $fetcher = $this->fetcher(['signatures.json' => [404, '']], $write);

        $this->assertFalse($fetcher->refresh());
    }

    public function testKeepsTheCacheWhenTheChecksumFileIsMalformed(): void
    {
        $write = $this->writeMock();
        $write->expects($this->never())->method('writeFile');

        $fetcher = $this->fetcher([
            'signatures.json' => [200, self::VALID_FEED],
            'signatures.json.sha256' => [200, 'not a checksum'],
        ], $write);

        $this->assertFalse($fetcher->refresh());
    }

    public function testKeepsTheCacheWhenTheFeedFailsValidationEvenWithAMatchingChecksum(): void
    {
        $invalidFeed = '{"signatures":[{"id":"a","name":"A","severity":"urgent","target":["pub_php"],'
            . '"pattern_type":"literal","pattern":"x"}]}';
        $checksum = hash('sha256', $invalidFeed) . "  signatures.json\n";

        $write = $this->writeMock();
        $write->expects($this->never())->method('writeFile');

        $fetcher = $this->fetcher([
            'signatures.json' => [200, $invalidFeed],
            'signatures.json.sha256' => [200, $checksum],
        ], $write);

        $this->assertFalse($fetcher->refresh());
    }
}
