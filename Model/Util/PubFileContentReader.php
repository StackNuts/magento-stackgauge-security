<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Util;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Filesystem;
use Throwable;

/**
 * Reads the content of files PubExecutableScanner already found, for ContentSignatureScanner
 * to check against "pub_php" signatures. Deliberately doesn't walk the filesystem itself -
 * PubExecutableScanner's own bounded, symlink-safe walk (see its docblock) already found the
 * exact candidate set worth reading content from; re-walking here would duplicate that safety
 * envelope for no benefit.
 *
 * Each file is capped at MAX_FILE_BYTES - a webshell is typically a few KB at most, so a file
 * far larger than that is either not worth reading in full for this purpose or risks memory
 * pressure on a large scan for no real detection benefit; it's skipped rather than truncated,
 * since a truncated read could itself produce a misleading partial match.
 */
class PubFileContentReader
{
    private const MAX_FILE_BYTES = 2_000_000;

    /**
     * @param Filesystem $filesystem
     */
    public function __construct(private readonly Filesystem $filesystem)
    {
    }

    /**
     * The content of each matched file, keyed by "pub_file:<relative path>".
     *
     * @param list<array> $matches As returned by PubExecutableScanner::scan().
     * @return array<string, string>
     */
    public function readContents(array $matches): array
    {
        try {
            $root = $this->filesystem->getDirectoryRead(DirectoryList::ROOT);
        } catch (Throwable) {
            return [];
        }

        $content = [];

        foreach ($matches as $match) {
            $relative = rtrim($match['directory'], '/') . '/' . ltrim($match['path'], '/');

            try {
                if (!$root->isExist($relative) || $root->stat($relative)['size'] > self::MAX_FILE_BYTES) {
                    continue;
                }

                $content['pub_file:' . $relative] = $root->readFile($relative);
            } catch (Throwable) {
                // Best-effort - one unreadable file must not stop the rest from being checked.
                continue;
            }
        }

        return $content;
    }
}
