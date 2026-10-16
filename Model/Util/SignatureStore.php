<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Util;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Filesystem;
use Magento\Framework\Module\Dir;
use Magento\Store\Model\ScopeInterface;
use Throwable;

/**
 * The signature set ContentSignatureScanner matches against. Prefers the most recently fetched
 * feed (see SignatureFeedFetcher), cached under var/, and falls back to the copy bundled in
 * etc/signatures.json when there is no cache yet, or the cache fails validation.
 *
 * The cache is verified on every read, not just when it's written: its stored detached Ed25519
 * signature (signatures.json.sig) must verify against the pinned keys (SignatureVerifier), and it
 * must pass SignatureSetValidator (which rejects an empty set). A cache that's corrupt, unsigned or
 * hand-edited is ignored rather than trusted. The cache is also ignored while the "Signature Feed
 * Updates" admin toggle is off, so Off really does mean bundled-only. The bundled set ships inside
 * the module and is only structurally validated. Neither source being usable is never an
 * error: getSignatures() returns [] and the reporter still reports whatever else it can.
 *
 * getSource() and getLastFeedFetch() exist purely so the dashboard can show *which* set is active
 * and how the last fetch attempt went - getSignatures()/getVersion() alone can't distinguish "a
 * freshly fetched feed happens to carry the same version as the bundled set" from "the fetch has
 * been failing and this is the fallback".
 */
class SignatureStore
{
    public const SOURCE_FEED = 'feed';
    public const SOURCE_BUNDLED = 'bundled';
    public const SOURCE_NONE = 'none';

    private const MODULE_NAME = 'StackNuts_StackGaugeSecurity';
    private const SIGNATURES_FILE = 'signatures.json';
    private const CACHE_PATH = 'stacknuts_stackgaugesecurity/signatures.json';
    private const CACHE_SIGNATURE_PATH = 'stacknuts_stackgaugesecurity/signatures.json.sig';
    private const XML_PATH_FEED_ENABLED = 'stacknuts_stackgauge/general/signature_feed_enabled';
    private const STATUS_PATH = 'stacknuts_stackgaugesecurity/feed_status.json';

    /**
     * @var array{0: string, 1: array<string, mixed>}|null Memoized resolve() result - the
     *     reporter calls getSignatures()/getVersion()/getSource() once each per request, and this
     *     keeps that at one pair of file reads rather than three.
     */
    private ?array $resolved = null;

    /**
     * @param Filesystem $filesystem
     * @param Dir $moduleDir
     * @param SafeFileReader $safeFileReader
     * @param SignatureSetValidator $validator
     * @param SignatureVerifier $verifier
     * @param ScopeConfigInterface $scopeConfig
     */
    public function __construct(
        private readonly Filesystem $filesystem,
        private readonly Dir $moduleDir,
        private readonly SafeFileReader $safeFileReader,
        private readonly SignatureSetValidator $validator,
        private readonly SignatureVerifier $verifier,
        private readonly ScopeConfigInterface $scopeConfig
    ) {
    }

    /**
     * Each entry has: id, name, severity, target (list<string>), pattern_type, pattern,
     * description.
     *
     * @return list<array<string, mixed>>
     */
    public function getSignatures(): array
    {
        return $this->loadActiveSet()['signatures'] ?? [];
    }

    /**
     * The active set's own version string (e.g. "2026.10.0"), or null if unknown - informational
     * only, so the signature set age/identity is visible on the dashboard.
     */
    public function getVersion(): ?string
    {
        $version = $this->loadActiveSet()['version'] ?? null;

        return is_string($version) ? $version : null;
    }

    /**
     * Which set getSignatures()/getVersion() are actually serving: SOURCE_FEED (a valid fetched
     * cache), SOURCE_BUNDLED (fell back to etc/signatures.json), or SOURCE_NONE (neither is
     * usable).
     */
    public function getSource(): string
    {
        return $this->resolve()[0];
    }

    /**
     * The most recent SignatureFeedFetcher::refresh() attempt, regardless of whether it succeeded
     * - {attempted_at, status: "success"|"failure", message: string|null, ref} - or null if the
     * feed has never been fetched (fresh install, feed fetch disabled, etc).
     *
     * @return array{attempted_at: string, status: string, message: string|null, ref: string}|null
     */
    public function getLastFeedFetch(): ?array
    {
        $var = $this->safeFileReader->getDirectoryRead($this->filesystem, DirectoryList::VAR_DIR);

        /** @var array{attempted_at: string, status: string, message: string|null, ref: string}|null */
        return $var !== null ? $this->safeFileReader->readJson($var, self::STATUS_PATH) : null;
    }

    /**
     * The fetched cache if it's present and valid, otherwise the bundled set, otherwise an empty
     * array.
     *
     * @return array<string, mixed>
     */
    private function loadActiveSet(): array
    {
        return $this->resolve()[1];
    }

    /**
     * @return array{0: string, 1: array<string, mixed>}
     */
    private function resolve(): array
    {
        if ($this->resolved !== null) {
            return $this->resolved;
        }

        $cache = $this->scopeConfig->isSetFlag(self::XML_PATH_FEED_ENABLED, ScopeInterface::SCOPE_STORE)
            ? $this->readValid($this->readCache())
            : null;
        if ($cache !== null) {
            return $this->resolved = [self::SOURCE_FEED, $cache];
        }

        $bundled = $this->readValid($this->readBundled());
        if ($bundled !== null) {
            return $this->resolved = [self::SOURCE_BUNDLED, $bundled];
        }

        return $this->resolved = [self::SOURCE_NONE, []];
    }

    /**
     * The cached feed, decoded, or null if it is missing, unsigned or its signature doesn't verify.
     *
     * @return array<string, mixed>|null
     */
    private function readCache(): ?array
    {
        $var = $this->safeFileReader->getDirectoryRead($this->filesystem, DirectoryList::VAR_DIR);
        if ($var === null) {
            return null;
        }

        $body = $this->safeFileReader->readRaw($var, self::CACHE_PATH);
        $signature = $this->safeFileReader->readRaw($var, self::CACHE_SIGNATURE_PATH);
        if ($body === null || $signature === null || !$this->verifier->isSignedByTrustedKey($body, $signature)) {
            return null;
        }

        $decoded = json_decode($body, true);

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function readBundled(): ?array
    {
        try {
            $etcDir = $this->filesystem->getDirectoryReadByPath(
                $this->moduleDir->getDir(self::MODULE_NAME, Dir::MODULE_ETC_DIR)
            );
        } catch (Throwable) {
            return null;
        }

        return $this->safeFileReader->readJson($etcDir, self::SIGNATURES_FILE);
    }

    /**
     * @param array<string, mixed>|null $decoded
     * @return array<string, mixed>|null
     */
    private function readValid(?array $decoded): ?array
    {
        return $decoded !== null && $this->validator->isValid($decoded) ? $decoded : null;
    }
}
