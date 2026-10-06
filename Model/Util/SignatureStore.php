<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Util;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Filesystem;
use Magento\Framework\Module\Dir;
use Magento\Framework\Serialize\Serializer\Json;
use Throwable;

/**
 * The signature set ContentSignatureScanner matches against. Prefers the most recently fetched
 * feed (see SignatureFeedFetcher), cached under var/, and falls back to the copy bundled in
 * etc/signatures.json when there is no cache yet, or the cache fails validation.
 *
 * Both sources are validated on every read, not just when they're written - a cache file that's
 * corrupt or hand-edited is ignored rather than trusted. Neither source being usable is never an
 * error: getSignatures() returns [] and the reporter still reports whatever else it can.
 */
class SignatureStore
{
    private const MODULE_NAME = 'StackNuts_StackGaugeSecurity';
    private const SIGNATURES_FILE = 'signatures.json';
    private const CACHE_PATH = 'stacknuts_stackgaugesecurity/signatures.json';

    /**
     * @param Filesystem $filesystem
     * @param Dir $moduleDir
     * @param Json $json
     * @param SignatureSetValidator $validator
     */
    public function __construct(
        private readonly Filesystem $filesystem,
        private readonly Dir $moduleDir,
        private readonly Json $json,
        private readonly SignatureSetValidator $validator
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
     * The fetched cache if it's present and valid, otherwise the bundled set, otherwise an empty
     * array.
     *
     * @return array<string, mixed>
     */
    private function loadActiveSet(): array
    {
        return $this->readValid($this->readCache()) ?? $this->readValid($this->readBundled()) ?? [];
    }

    /**
     * @return array<string, mixed>|null
     */
    private function readCache(): ?array
    {
        try {
            $var = $this->filesystem->getDirectoryRead(DirectoryList::VAR_DIR);
            if (!$var->isExist(self::CACHE_PATH)) {
                return null;
            }

            $decoded = $this->json->unserialize($var->readFile(self::CACHE_PATH));

            return is_array($decoded) ? $decoded : null;
        } catch (Throwable) {
            return null;
        }
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

            if (!$etcDir->isExist(self::SIGNATURES_FILE)) {
                return null;
            }

            $decoded = $this->json->unserialize($etcDir->readFile(self::SIGNATURES_FILE));

            return is_array($decoded) ? $decoded : null;
        } catch (Throwable) {
            return null;
        }
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
