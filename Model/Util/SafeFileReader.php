<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Util;

use Magento\Framework\Filesystem;
use Magento\Framework\Filesystem\Directory\ReadInterface;
use Magento\Framework\Serialize\Serializer\Json;
use Throwable;

/**
 * Wraps the two filesystem idioms repeated across this module's scanners and stores: resolving a
 * Magento directory read (or an absolute path within one) that may not exist or be reachable, and
 * reading+decoding a JSON file that may be missing or malformed. Both are best-effort - every
 * method returns null rather than throwing, so a missing/unreadable/corrupt file never stops a
 * caller from reporting whatever else it still can.
 */
class SafeFileReader
{
    /**
     * @param Json $json
     */
    public function __construct(private readonly Json $json)
    {
    }

    /**
     * $filesystem->getDirectoryRead($directoryCode), or null if that throws.
     *
     * Null covers e.g. a directory code that doesn't exist on this install.
     *
     * @param Filesystem $filesystem
     * @param string $directoryCode One of Magento\Framework\App\Filesystem\DirectoryList::*.
     */
    public function getDirectoryRead(Filesystem $filesystem, string $directoryCode): ?ReadInterface
    {
        try {
            return $filesystem->getDirectoryRead($directoryCode);
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * The absolute path of $relativePath within $directoryCode, or null if it can't be resolved.
     *
     * @param Filesystem $filesystem
     * @param string $directoryCode One of Magento\Framework\App\Filesystem\DirectoryList::*.
     * @param string $relativePath
     */
    public function resolveAbsolutePath(Filesystem $filesystem, string $directoryCode, string $relativePath): ?string
    {
        $directory = $this->getDirectoryRead($filesystem, $directoryCode);
        if ($directory === null) {
            return null;
        }

        try {
            return $directory->getAbsolutePath($relativePath);
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Reads and JSON-decodes $relativePath from $directory, or null on any failure.
     *
     * Covers a missing or unreadable file and content that doesn't decode to an array.
     *
     * @param ReadInterface $directory
     * @param string $relativePath
     * @return array<string, mixed>|null
     */
    public function readJson(ReadInterface $directory, string $relativePath): ?array
    {
        try {
            if (!$directory->isExist($relativePath)) {
                return null;
            }

            $decoded = $this->json->unserialize($directory->readFile($relativePath));

            return is_array($decoded) ? $decoded : null;
        } catch (Throwable) {
            return null;
        }
    }
}
