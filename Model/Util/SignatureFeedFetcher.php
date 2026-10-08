<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Util;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Filesystem;
use Magento\Framework\HTTP\Client\Curl;
use Magento\Framework\Serialize\Serializer\Json;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Downloads the published signature set from the StackNuts signatures repo and caches it under
 * var/. Only a fetch that passes both checks replaces the cache: the body must hash to the
 * published SHA-256 (catches a truncated or tampered transfer), and it must pass
 * SignatureSetValidator. Anything else leaves the previous good cache in place - a bad fetch
 * never degrades detection below what was already working.
 *
 * Every attempt - success or failure - is recorded to a small status file under var/ (read back by
 * SignatureStore::getLastFeedFetch()) so the dashboard can show when the feed was last checked and
 * why it isn't using a freshly fetched set, rather than that being visible only in the PHP log.
 *
 * FEED_REF is the git ref the feed is read from. It points at main for now so the feed can be
 * exercised before a first tagged release exists; once tags are being published it should be
 * changed to a pinned release tag, so a bad commit on main can't reach client stores before it's
 * been released.
 */
class SignatureFeedFetcher
{
    public const FEED_REF = 'main';
    private const FEED_BASE_URL = 'https://raw.githubusercontent.com/StackNuts/magento-stackgauge-signatures/';
    private const FEED_FILE = 'signatures.json';
    private const CHECKSUM_FILE = 'signatures.json.sha256';
    private const STATUS_FILE = 'feed_status.json';
    private const CONNECT_TIMEOUT_SECONDS = 5;
    private const TOTAL_TIMEOUT_SECONDS = 10;
    private const CACHE_DIR = 'stacknuts_stackgaugesecurity';

    /**
     * @param Curl $curl
     * @param Filesystem $filesystem
     * @param SignatureSetValidator $validator
     * @param Json $json
     * @param LoggerInterface $logger
     */
    public function __construct(
        private readonly Curl $curl,
        private readonly Filesystem $filesystem,
        private readonly SignatureSetValidator $validator,
        private readonly Json $json,
        private readonly LoggerInterface $logger
    ) {
    }

    /**
     * Fetches, verifies, and caches the feed. Returns false (and logs why) on any failure, leaving
     * the existing cache untouched.
     */
    public function refresh(): bool
    {
        try {
            $body = $this->download(self::FEED_FILE);
            $expectedHash = $this->parseChecksum($this->download(self::CHECKSUM_FILE));

            if ($body === null || $expectedHash === null) {
                return $this->fail(
                    'signature feed download failed; keeping cached set.',
                    'signature feed download failed'
                );
            }

            if (!hash_equals($expectedHash, hash('sha256', $body))) {
                return $this->fail(
                    'signature feed checksum mismatch; keeping cached set.',
                    'signature feed checksum mismatch'
                );
            }

            $decoded = $this->json->unserialize($body);
            if (!is_array($decoded) || !$this->validator->isValid($decoded)) {
                return $this->fail(
                    'signature feed failed validation; keeping cached set.',
                    'signature feed failed validation'
                );
            }

            $this->writeCache($body);
            $this->recordStatus(true, null);
            return true;
        } catch (Throwable $e) {
            return $this->fail(
                'signature feed refresh failed: ' . $e->getMessage(),
                'signature feed refresh failed: ' . $e->getMessage()
            );
        }
    }

    /**
     * Logs $logMessage, records $statusMessage as this attempt's failure reason, and returns
     * false - the shared tail of every failure branch in refresh().
     */
    private function fail(string $logMessage, string $statusMessage): bool
    {
        $this->logger->warning('StackGaugeSecurity: ' . $logMessage);
        $this->recordStatus(false, $statusMessage);

        return false;
    }

    private function download(string $file): ?string
    {
        $this->curl->setOptions([
            CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT_SECONDS,
            CURLOPT_TIMEOUT => self::TOTAL_TIMEOUT_SECONDS,
        ]);
        $this->curl->get(self::FEED_BASE_URL . self::FEED_REF . '/' . $file);

        return $this->curl->getStatus() === 200 ? $this->curl->getBody() : null;
    }

    /**
     * The checksum file is in sha256sum format: "<64 hex chars>  <filename>". Only the hash matters.
     */
    private function parseChecksum(?string $contents): ?string
    {
        if ($contents === null || !preg_match('/^([0-9a-f]{64})\b/i', trim($contents), $match)) {
            return null;
        }

        return strtolower($match[1]);
    }

    /**
     * Writes to a temp file and renames over the cache, so a reader never sees a half-written file.
     */
    private function writeCache(string $body): void
    {
        $var = $this->filesystem->getDirectoryWrite(DirectoryList::VAR_DIR);
        $var->create(self::CACHE_DIR);

        $tmp = self::CACHE_DIR . '/' . self::FEED_FILE . '.tmp';
        $var->writeFile($tmp, $body);
        $var->renameFile($tmp, self::CACHE_DIR . '/' . self::FEED_FILE);
    }

    /**
     * Records this attempt's outcome so SignatureStore::getLastFeedFetch() can surface it - best
     * effort only, since a failure to record the status must never be mistaken for a failure to
     * refresh the feed itself.
     */
    private function recordStatus(bool $success, ?string $message): void
    {
        try {
            $payload = $this->json->serialize([
                'attempted_at' => gmdate('Y-m-d\TH:i:s\Z'),
                'status' => $success ? 'success' : 'failure',
                'message' => $message,
                'ref' => self::FEED_REF,
            ]);

            $var = $this->filesystem->getDirectoryWrite(DirectoryList::VAR_DIR);
            $var->create(self::CACHE_DIR);

            $tmp = self::CACHE_DIR . '/' . self::STATUS_FILE . '.tmp';
            $var->writeFile($tmp, $payload);
            $var->renameFile($tmp, self::CACHE_DIR . '/' . self::STATUS_FILE);
        } catch (Throwable) {
            // Best-effort only - see docblock.
        }
    }
}
