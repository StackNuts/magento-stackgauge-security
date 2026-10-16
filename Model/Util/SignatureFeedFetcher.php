<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Util;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Filesystem;
use Magento\Framework\HTTP\Client\CurlFactory;
use Magento\Framework\Serialize\Serializer\Json;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Downloads the published signature set from the StackNuts signatures repo and caches it under
 * var/. Only a fetch that passes every check replaces the cache:
 *
 * - its detached Ed25519 signature (signatures.json.sig) verifies against one of the keys pinned in
 *   SignatureVerifier::TRUSTED_KEYS - so neither someone able to push to the signatures repo
 *   nor anything between here and GitHub can get rules onto a store, yet a new set still ships
 *   the moment a signed release lands on main, with no module update;
 * - its version is not older than the cached set's (the cache is only used as a baseline if its
 *   own stored signature still verifies), so an old, validly signed feed can't be replayed to
 *   roll detections back;
 * - it passes SignatureSetValidator.
 *
 * The signature is stored next to the cache (signatures.json.sig) and re-verified on every read by
 * SignatureStore. Anything else leaves the previous good cache in place - a bad fetch never
 * degrades detection below what was already working.
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
    private const SIGNATURE_FILE = 'signatures.json.sig';
    private const STATUS_FILE = 'feed_status.json';
    private const CONNECT_TIMEOUT_SECONDS = 5;
    private const TOTAL_TIMEOUT_SECONDS = 10;
    private const CACHE_DIR = 'stacknuts_stackgaugesecurity';

    /**
     * A CurlFactory rather than a shared Curl - Magento's shared instance keeps whatever headers
     * the last caller set (StackGauge's dashboard Authorization header, a Cloudflare API token),
     * which would otherwise be sent to GitHub along with this request.
     *
     * @param CurlFactory $curlFactory
     * @param Filesystem $filesystem
     * @param SignatureSetValidator $validator
     * @param Json $json
     * @param LoggerInterface $logger
     * @param SignatureVerifier $verifier Holds the pinned trusted keys.
     */
    public function __construct(
        private readonly CurlFactory $curlFactory,
        private readonly Filesystem $filesystem,
        private readonly SignatureSetValidator $validator,
        private readonly Json $json,
        private readonly LoggerInterface $logger,
        private readonly SignatureVerifier $verifier
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
            $signature = $this->download(self::SIGNATURE_FILE);

            if ($body === null || $signature === null) {
                return $this->fail(
                    'signature feed download failed; keeping cached set.',
                    'signature feed download failed'
                );
            }

            if (!$this->verifier->isSignedByTrustedKey($body, $signature)) {
                return $this->fail(
                    'signature feed is not signed by a trusted key; keeping cached set.',
                    'signature feed signature invalid'
                );
            }

            $decoded = $this->json->unserialize($body);
            if (!is_array($decoded) || !$this->validator->isValid($decoded)) {
                return $this->fail(
                    'signature feed failed validation; keeping cached set.',
                    'signature feed failed validation'
                );
            }

            if ($this->isOlderThanCache($decoded)) {
                return $this->fail(
                    'signature feed is older than the cached set; keeping cached set.',
                    'signature feed older than cached set'
                );
            }

            $this->writeCache($body, $signature);
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

    /**
     * $file's body from the feed repo at FEED_REF, or null on anything but a 200.
     *
     * @param string $file
     */
    private function download(string $file): ?string
    {
        $curl = $this->curlFactory->create();
        $curl->setOptions([
            CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT_SECONDS,
            CURLOPT_TIMEOUT => self::TOTAL_TIMEOUT_SECONDS,
        ]);
        $curl->get(self::FEED_BASE_URL . self::FEED_REF . '/' . $file);

        return $curl->getStatus() === 200 ? $curl->getBody() : null;
    }

    /**
     * The currently cached feed, decoded - but only if its stored signature still verifies. A
     * cache that is missing, unsigned or fails verification is treated as absent, so it can neither
     * block a genuine feed (e.g. a planted "version 9999") nor be used as the baseline.
     *
     * @return array<string, mixed>|null
     */
    private function verifiedCache(): ?array
    {
        $var = $this->filesystem->getDirectoryWrite(DirectoryList::VAR_DIR);
        $cachePath = self::CACHE_DIR . '/' . self::FEED_FILE;
        $sigPath = self::CACHE_DIR . '/' . self::SIGNATURE_FILE;

        if (!$var->isExist($cachePath) || !$var->isExist($sigPath)) {
            return null;
        }

        $body = $var->readFile($cachePath);
        if (!$this->verifier->isSignedByTrustedKey($body, $var->readFile($sigPath))) {
            return null;
        }

        $cached = json_decode($body, true);

        return is_array($cached) ? $cached : null;
    }

    /**
     * Whether $decoded's version is older than the currently cached feed's. A missing or
     * unverifiable cache (first fetch) is never "newer".
     *
     * @param array<string, mixed> $decoded
     */
    private function isOlderThanCache(array $decoded): bool
    {
        $cached = $this->verifiedCache();
        $cachedVersion = $cached['version'] ?? null;
        $newVersion = $decoded['version'] ?? null;

        if (!is_string($cachedVersion) || !is_string($newVersion)) {
            return false;
        }

        return version_compare($newVersion, $cachedVersion, '<');
    }

    /**
     * Writes to a temp file and renames over the cache, so a reader never sees a half-written file.
     */
    private function writeCache(string $body, string $signature): void
    {
        $var = $this->filesystem->getDirectoryWrite(DirectoryList::VAR_DIR);
        $var->create(self::CACHE_DIR);

        // The signature goes in first: a reader that sees the new body always finds a signature
        // that matches it or (briefly) the old one, which fails verification and falls back to the
        // bundled set rather than trusting an unsigned file.
        foreach ([self::SIGNATURE_FILE => $signature, self::FEED_FILE => $body] as $file => $content) {
            $tmp = self::CACHE_DIR . '/' . $file . '.tmp';
            $var->writeFile($tmp, $content);
            $var->renameFile($tmp, self::CACHE_DIR . '/' . $file);
        }
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
