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
use Magento\Framework\HTTP\Client\CurlFactory;
use Magento\Framework\Serialize\Serializer\Json;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureFeedFetcher;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureSetValidator;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureVerifier;

class SignatureFeedFetcherTest extends TestCase
{
    private const VALID_FEED = '{"version":"2026.10.0","signatures":[{"id":"a","name":"A","severity":"critical",'
        . '"target":["pub_php"],"pattern_type":"literal","pattern":"marker"}]}';

    /**
     * A throwaway keypair, trusted as "test-key" by every fetcher this test builds.
     */
    private string $keypair;

    protected function setUp(): void
    {
        $this->keypair = sodium_crypto_sign_keypair();
    }

    /**
     * signatures.json.sig contents for $body signed with $secretKey (this test's own by default).
     *
     * @param string $body
     * @param string|null $secretKey
     * @param string $keyId
     */
    private function sign(string $body, ?string $secretKey = null, string $keyId = 'test-key'): string
    {
        return (string)json_encode([
            'algorithm' => 'ed25519',
            'key_id' => $keyId,
            'signature' => base64_encode(
                sodium_crypto_sign_detached($body, $secretKey ?? sodium_crypto_sign_secretkey($this->keypair))
            ),
        ]);
    }

    /**
     * @param array<string, array{0: int, 1: string}> $responses Keyed by the URL's filename,
     *     e.g. "signatures.json", mapped to [http status, body].
     */
    private function fetcher(array $responses, WriteInterface $write, ?LoggerInterface $logger = null): SignatureFeedFetcher
    {
        $current = '';
        $curl = $this->createStub(Curl::class);
        $curlFactory = $this->createStub(CurlFactory::class);
        $curlFactory->method('create')->willReturn($curl);
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
            $curlFactory,
            $filesystem,
            new SignatureSetValidator(),
            new Json(),
            $logger ?? $this->createStub(LoggerInterface::class),
            new SignatureVerifier(['test-key' => base64_encode(sodium_crypto_sign_publickey($this->keypair))])
        );
    }

    /**
     * @return array{0: WriteInterface, 1: object{written: list<string>, contents: array<string, string>}}
     */
    private function recordingWrite(?string $cachedFeed = null, ?string $cachedSignature = 'auto'): array
    {
        if ($cachedSignature === 'auto') {
            $cachedSignature = $cachedFeed === null ? null : $this->sign($cachedFeed);
        }

        $recorder = new \stdClass();
        $recorder->written = [];
        $recorder->contents = [];

        $write = $this->createStub(WriteInterface::class);
        $write->method('isExist')->willReturnCallback(
            static fn (string $path): bool => str_ends_with($path, '.sig')
                ? $cachedSignature !== null
                : $cachedFeed !== null
        );
        $write->method('readFile')->willReturnCallback(
            static fn (string $path): string => str_ends_with($path, '.sig')
                ? (string)$cachedSignature
                : (string)$cachedFeed
        );
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

    public function testCachesTheFeedWhenTheSignatureAndValidationPass(): void
    {
        [$write, $recorder] = $this->recordingWrite();

        $fetcher = $this->fetcher([
            'signatures.json' => [200, self::VALID_FEED],
            'signatures.json.sig' => [200, $this->sign(self::VALID_FEED)],
        ], $write);

        $this->assertTrue($fetcher->refresh());
        $this->assertContains('stacknuts_stackgaugesecurity/signatures.json', $recorder->written);
        $this->assertSame(
            $this->sign(self::VALID_FEED),
            $recorder->contents['stacknuts_stackgaugesecurity/signatures.json.sig']
        );

        $status = json_decode($recorder->contents['stacknuts_stackgaugesecurity/feed_status.json'], true);
        $this->assertSame('success', $status['status']);
        $this->assertNull($status['message']);
    }

    public function testRejectsAFeedSignedByAnUntrustedKey(): void
    {
        [$write, $recorder] = $this->recordingWrite();
        $attackerKey = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());

        $fetcher = $this->fetcher([
            'signatures.json' => [200, self::VALID_FEED],
            'signatures.json.sig' => [200, $this->sign(self::VALID_FEED, $attackerKey)],
        ], $write);

        $this->assertFalse($fetcher->refresh());
        $this->assertNotContains('stacknuts_stackgaugesecurity/signatures.json', $recorder->written);

        $status = json_decode($recorder->contents['stacknuts_stackgaugesecurity/feed_status.json'], true);
        $this->assertSame('signature feed signature invalid', $status['message']);
    }

    /**
     * What a compromise of the signatures repo looks like: a changed feed with the old, still
     * valid-looking signature (or a freshly regenerated SHA-256) alongside it.
     */
    public function testRejectsAFeedModifiedAfterSigning(): void
    {
        [$write, $recorder] = $this->recordingWrite();
        $tampered = str_replace('marker', 'something-else', self::VALID_FEED);

        $fetcher = $this->fetcher([
            'signatures.json' => [200, $tampered],
            'signatures.json.sig' => [200, $this->sign(self::VALID_FEED)],
            'signatures.json.sha256' => [200, hash('sha256', $tampered) . "  signatures.json\n"],
        ], $write);

        $this->assertFalse($fetcher->refresh());
        $this->assertNotContains('stacknuts_stackgaugesecurity/signatures.json', $recorder->written);
    }

    public function testRejectsAFeedWithAnUnknownKeyIdOrMalformedSignatureFile(): void
    {
        foreach ([$this->sign(self::VALID_FEED, null, 'unknown-key'), 'not json', '{"algorithm":"rsa"}'] as $sigFile) {
            [$write, $recorder] = $this->recordingWrite();

            $fetcher = $this->fetcher([
                'signatures.json' => [200, self::VALID_FEED],
                'signatures.json.sig' => [200, $sigFile],
            ], $write);

            $this->assertFalse($fetcher->refresh(), $sigFile);
            $this->assertNotContains('stacknuts_stackgaugesecurity/signatures.json', $recorder->written);
        }
    }

    public function testRejectsAnOlderValidlySignedFeedThanTheCachedOne(): void
    {
        $newerCache = str_replace('2026.10.0', '2026.11.0', self::VALID_FEED);
        [$write, $recorder] = $this->recordingWrite($newerCache);

        $fetcher = $this->fetcher([
            'signatures.json' => [200, self::VALID_FEED],
            'signatures.json.sig' => [200, $this->sign(self::VALID_FEED)],
        ], $write);

        $this->assertFalse($fetcher->refresh());
        $this->assertNotContains('stacknuts_stackgaugesecurity/signatures.json', $recorder->written);

        $status = json_decode($recorder->contents['stacknuts_stackgaugesecurity/feed_status.json'], true);
        $this->assertSame('signature feed older than cached set', $status['message']);
    }

    /**
     * A planted cache ("version 9999", unsigned or badly signed) must not block every real feed
     * as "older" forever.
     */
    public function testAnUnverifiableCacheDoesNotBlockARealFeed(): void
    {
        $planted = str_replace('2026.10.0', '9999.0', self::VALID_FEED);

        foreach ([null, 'forged'] as $cachedSignature) {
            [$write, $recorder] = $this->recordingWrite($planted, $cachedSignature);

            $fetcher = $this->fetcher([
                'signatures.json' => [200, self::VALID_FEED],
                'signatures.json.sig' => [200, $this->sign(self::VALID_FEED)],
            ], $write);

            $this->assertTrue($fetcher->refresh());
            $this->assertContains('stacknuts_stackgaugesecurity/signatures.json', $recorder->written);
        }
    }

    public function testRejectsAValidlySignedEmptyFeed(): void
    {
        $empty = '{"version":"2026.12.0","signatures":[]}';
        [$write] = $this->recordingWrite();

        $fetcher = $this->fetcher([
            'signatures.json' => [200, $empty],
            'signatures.json.sig' => [200, $this->sign($empty)],
        ], $write);

        $this->assertFalse($fetcher->refresh());
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

    public function testKeepsTheCacheWhenTheFeedFailsValidationEvenWhenValidlySigned(): void
    {
        $invalidFeed = '{"signatures":[{"id":"a","name":"A","severity":"urgent","target":["pub_php"],'
            . '"pattern_type":"literal","pattern":"x"}]}';

        [$write, $recorder] = $this->recordingWrite();

        $fetcher = $this->fetcher([
            'signatures.json' => [200, $invalidFeed],
            'signatures.json.sig' => [200, $this->sign($invalidFeed)],
        ], $write);

        $this->assertFalse($fetcher->refresh());
        $this->assertNotContains('stacknuts_stackgaugesecurity/signatures.json', $recorder->written);

        $status = json_decode($recorder->contents['stacknuts_stackgaugesecurity/feed_status.json'], true);
        $this->assertSame('failure', $status['status']);
        $this->assertSame('signature feed failed validation', $status['message']);
    }

    /**
     * Guards against a malformed key being pinned - a bad entry would silently reject every feed.
     */
    public function testThePinnedProductionKeysAreWellFormed(): void
    {
        $keys = SignatureVerifier::TRUSTED_KEYS;

        $this->assertNotEmpty($keys);
        foreach ($keys as $keyId => $publicKey) {
            $this->assertMatchesRegularExpression('/^[a-z0-9-]+$/', $keyId);
            $this->assertSame(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, strlen((string)base64_decode($publicKey, true)));
        }
    }
}
