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

    /**
     * @return array{0: WriteInterface, 1: object{written: list<string>, contents: array<string, string>}}
     */
    private function recordingWrite(): array
    {
        $recorder = new \stdClass();
        $recorder->written = [];
        $recorder->contents = [];

        $write = $this->createStub(WriteInterface::class);
        $write->method('create')->willReturn(true);
        $write->method('writeFile')->willReturnCallback(
            function (string $path, string $content) use ($recorder): int {
                $recorder->written[] = $path;
                $recorder->contents[$path] = $content;
                return strlen($content);
            }
        );
        $write->method('renameFile')->willReturnCallback(
            function (string $from, string $to) use ($recorder): bool {
                $recorder->written[] = $to;
                $recorder->contents[$to] = $recorder->contents[$from] ?? null;
                return true;
            }
        );

        return [$write, $recorder];
    }

    public function testCachesTheFeedWhenChecksumAndValidationPass(): void
    {
        $checksum = hash('sha256', self::VALID_FEED) . "  signatures.json\n";
        [$write, $recorder] = $this->recordingWrite();

        $fetcher = $this->fetcher([
            'signatures.json' => [200, self::VALID_FEED],
            'signatures.json.sha256' => [200, $checksum],
        ], $write);

        $this->assertTrue($fetcher->refresh());
        $this->assertContains('stacknuts_stackgaugesecurity/signatures.json', $recorder->written);

        $status = json_decode($recorder->contents['stacknuts_stackgaugesecurity/feed_status.json'], true);
        $this->assertSame('success', $status['status']);
        $this->assertNull($status['message']);
    }

    public function testKeepsTheCacheWhenTheChecksumDoesNotMatch(): void
    {
        [$write, $recorder] = $this->recordingWrite();

        $fetcher = $this->fetcher([
            'signatures.json' => [200, self::VALID_FEED],
            'signatures.json.sha256' => [200, str_repeat('0', 64) . "  signatures.json\n"],
        ], $write);

        $this->assertFalse($fetcher->refresh());
        $this->assertNotContains('stacknuts_stackgaugesecurity/signatures.json', $recorder->written);

        $status = json_decode($recorder->contents['stacknuts_stackgaugesecurity/feed_status.json'], true);
        $this->assertSame('failure', $status['status']);
        $this->assertSame('signature feed checksum mismatch', $status['message']);
    }

    public function testKeepsTheCacheWhenTheFeedCannotBeDownloaded(): void
    {
        [$write, $recorder] = $this->recordingWrite();

        $fetcher = $this->fetcher(['signatures.json' => [404, '']], $write);

        $this->assertFalse($fetcher->refresh());
        $this->assertNotContains('stacknuts_stackgaugesecurity/signatures.json', $recorder->written);

        $status = json_decode($recorder->contents['stacknuts_stackgaugesecurity/feed_status.json'], true);
        $this->assertSame('failure', $status['status']);
        $this->assertSame('signature feed download failed', $status['message']);
    }

    public function testKeepsTheCacheWhenTheChecksumFileIsMalformed(): void
    {
        [$write, $recorder] = $this->recordingWrite();

        $fetcher = $this->fetcher([
            'signatures.json' => [200, self::VALID_FEED],
            'signatures.json.sha256' => [200, 'not a checksum'],
        ], $write);

        $this->assertFalse($fetcher->refresh());
        $this->assertNotContains('stacknuts_stackgaugesecurity/signatures.json', $recorder->written);
    }

    public function testKeepsTheCacheWhenTheFeedFailsValidationEvenWithAMatchingChecksum(): void
    {
        $invalidFeed = '{"signatures":[{"id":"a","name":"A","severity":"urgent","target":["pub_php"],'
            . '"pattern_type":"literal","pattern":"x"}]}';
        $checksum = hash('sha256', $invalidFeed) . "  signatures.json\n";

        [$write, $recorder] = $this->recordingWrite();

        $fetcher = $this->fetcher([
            'signatures.json' => [200, $invalidFeed],
            'signatures.json.sha256' => [200, $checksum],
        ], $write);

        $this->assertFalse($fetcher->refresh());
        $this->assertNotContains('stacknuts_stackgaugesecurity/signatures.json', $recorder->written);

        $status = json_decode($recorder->contents['stacknuts_stackgaugesecurity/feed_status.json'], true);
        $this->assertSame('failure', $status['status']);
        $this->assertSame('signature feed failed validation', $status['message']);
    }
}
