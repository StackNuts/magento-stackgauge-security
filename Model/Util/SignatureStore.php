<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Util;

use Magento\Framework\Filesystem;
use Magento\Framework\Module\Dir;
use Magento\Framework\Serialize\Serializer\Json;
use Throwable;

/**
 * Reads this module's bundled signature set (etc/signatures.json), the hand-curated,
 * StackNuts-authored content-signature list that ContentSignatureScanner matches against.
 *
 * This is deliberately the only source right now - there is no live fetch of any kind. A
 * future auto-updating feed (fetched, checksum-verified, and cached) is expected to layer in
 * ahead of this as a preferred source later, falling back to this bundled file when unset or
 * stale - this class's single getSignatures() method is the seam that split will happen
 * behind, so nothing calling it needs to change.
 *
 * A missing or malformed signatures.json is never a hard error here - same reasoning as
 * StackGauge\Model\Util\ComposerLockReader: a broken signature file must not stop the
 * reporter from reporting whatever else it still can, so this returns an empty list rather
 * than throwing.
 */
class SignatureStore
{
    private const MODULE_NAME = 'StackNuts_StackGaugeSecurity';
    private const SIGNATURES_FILE = 'signatures.json';

    /**
     * @param Filesystem $filesystem
     * @param Dir $moduleDir
     * @param Json $json
     */
    public function __construct(
        private readonly Filesystem $filesystem,
        private readonly Dir $moduleDir,
        private readonly Json $json
    ) {
    }

    /**
     * Every signature in the bundled set, or an empty list if it's missing/malformed.
     *
     * Each entry has: id, name, severity, target (list<string>), pattern_type, pattern,
     * description.
     *
     * @return list<array<string, mixed>>
     */
    public function getSignatures(): array
    {
        try {
            $etcDir = $this->filesystem->getDirectoryReadByPath(
                $this->moduleDir->getDir(self::MODULE_NAME, Dir::MODULE_ETC_DIR)
            );

            if (!$etcDir->isExist(self::SIGNATURES_FILE)) {
                return [];
            }

            $decoded = $this->json->unserialize($etcDir->readFile(self::SIGNATURES_FILE));

            return is_array($decoded['signatures'] ?? null) ? $decoded['signatures'] : [];
        } catch (Throwable) {
            return [];
        }
    }

    /**
     * The bundled signature set's own version string (e.g. "2026.10.0"), or null if it's
     * missing/malformed - opaque, informational only, so the reported signature set age/
     * identity is visible on the dashboard.
     */
    public function getVersion(): ?string
    {
        try {
            $etcDir = $this->filesystem->getDirectoryReadByPath(
                $this->moduleDir->getDir(self::MODULE_NAME, Dir::MODULE_ETC_DIR)
            );

            if (!$etcDir->isExist(self::SIGNATURES_FILE)) {
                return null;
            }

            $decoded = $this->json->unserialize($etcDir->readFile(self::SIGNATURES_FILE));

            return is_string($decoded['version'] ?? null) ? $decoded['version'] : null;
        } catch (Throwable) {
            return null;
        }
    }
}
