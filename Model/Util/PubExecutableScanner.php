<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Util;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Filesystem;
use SplFileInfo;

/**
 * Bounded recursive scan of pub/media and pub/static for executable-extension files that have
 * no business being there - these directories are supposed to hold only images, CSS, JS, and
 * other static assets, so any .php/.phtml/.phar file found is a strong webshell signal (the
 * classic post-upload-vulnerability drop location, and one nginx in particular often doesn't
 * block execution of even when Magento's own pub/media/.htaccess says to - that's an
 * Apache-only mechanism).
 *
 * pub/media especially can hold hundreds of thousands of files on a large catalog (every
 * resized product image variant lives under catalog/product/cache) - walking it naively has
 * previously stalled PHP-FPM on real stores. This is bounded on every axis that matters: a
 * hard cap on total files visited (not just matches), a max depth, never follows symlinks
 * (common in dev-mode setups, which would otherwise risk loops or turn this into scanning the
 * entire theme source tree), and prunes the known-huge, categorically-image-only cache
 * subdirectories before ever descending into them rather than visiting and discarding.
 *
 * This walks the local filesystem directly via SPL iterators rather than through Magento's own
 * Filesystem\DriverInterface abstraction - simpler and faster for a plain bounded local walk,
 * but it means a store using a remote/cloud media storage driver gets a scan that silently
 * finds nothing rather than an error. Treat a clean result from this scanner as "nothing found
 * on local disk", not an absolute guarantee.
 */
class PubExecutableScanner
{
    private const MAX_INODES_VISITED_PER_DIRECTORY = 2500;
    private const MAX_DEPTH = 8;
    private const MAX_MATCHES = 80;

    /**
     * @var list<string>
     */
    private const SCAN_DIRECTORIES = ['pub/media', 'pub/static'];

    /**
     * @var list<string>
     */
    private const EXECUTABLE_EXTENSIONS = ['php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'pht'];

    /**
     * Subdirectory names (matched anywhere in the tree, not just at the root) that are large,
     * image/asset-only, and not worth the walk budget - pruned before ever descending into
     * them, rather than visited and discarded.
     *
     * @var list<string>
     */
    private const PRUNED_DIRECTORY_NAMES = ['cache', 'tmp'];

    /**
     * @param Filesystem $filesystem
     * @param SafeFileReader $safeFileReader
     * @param BoundedDirectoryWalker $walker
     */
    public function __construct(
        private readonly Filesystem $filesystem,
        private readonly SafeFileReader $safeFileReader,
        private readonly BoundedDirectoryWalker $walker
    ) {
    }

    /**
     * Scans pub/media and pub/static for unexpected executable-extension files.
     *
     * @return list<array{directory: string, path: string}>
     */
    public function scan(): array
    {
        $matches = [];

        foreach (self::SCAN_DIRECTORIES as $relativeDir) {
            foreach ($this->scanDirectory($relativeDir) as $match) {
                $matches[] = $match;
                if (count($matches) >= self::MAX_MATCHES) {
                    return $matches;
                }
            }
        }

        return $matches;
    }

    /**
     * Bounded scan of one directory - see this class's own docblock for the safety bounds.
     *
     * @param string $relativeDir
     * @return list<array{directory: string, path: string}>
     */
    private function scanDirectory(string $relativeDir): array
    {
        $absolutePath = $this->safeFileReader->resolveAbsolutePath(
            $this->filesystem,
            DirectoryList::ROOT,
            $relativeDir
        );
        if ($absolutePath === null) {
            return [];
        }

        $absolutePath = rtrim($absolutePath, '/');
        $matches = [];
        $visited = 0;

        $this->walker->walk(
            $absolutePath,
            self::MAX_DEPTH,
            static fn (SplFileInfo $file): bool => !$file->isDir() || !in_array(
                strtolower($file->getFilename()),
                self::PRUNED_DIRECTORY_NAMES,
                true
            ),
            function (SplFileInfo $file) use (&$matches, &$visited, $relativeDir, $absolutePath): bool {
                $visited++;
                if ($visited > self::MAX_INODES_VISITED_PER_DIRECTORY) {
                    return false;
                }

                if (!$file->isFile()) {
                    return true;
                }

                if (!in_array(strtolower($file->getExtension()), self::EXECUTABLE_EXTENSIONS, true)) {
                    return true;
                }

                $matches[] = [
                    'directory' => $relativeDir,
                    'path' => ltrim(substr($file->getPathname(), strlen($absolutePath)), '/'),
                ];

                return count($matches) < self::MAX_MATCHES;
            }
        );

        return $matches;
    }
}
