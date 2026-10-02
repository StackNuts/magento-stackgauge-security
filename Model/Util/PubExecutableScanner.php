<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Util;

use FilesystemIterator;
use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Filesystem;
use RecursiveCallbackFilterIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use Throwable;

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
     */
    public function __construct(private readonly Filesystem $filesystem)
    {
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
        try {
            $absolutePath = rtrim(
                $this->filesystem->getDirectoryRead(DirectoryList::ROOT)->getAbsolutePath($relativeDir),
                '/'
            );
        } catch (Throwable) {
            return [];
        }

        // phpcs:ignore Magento2.Functions.DiscouragedFunction.DiscouragedWithAlternative,Magento2.Functions.DiscouragedFunction.Discouraged
        if (!is_dir($absolutePath) || is_link($absolutePath)) {
            return [];
        }

        $matches = [];
        $visited = 0;

        try {
            $flags = FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS;
            $filtered = new RecursiveCallbackFilterIterator(
                new RecursiveDirectoryIterator($absolutePath, $flags),
                static function (SplFileInfo $file): bool {
                    // Never descend into (or even report on) a symlink - dev-mode setups
                    // commonly symlink pub/static back into theme source trees, and following
                    // that would turn this into an unbounded full-codebase scan. Omitting
                    // FilesystemIterator::FOLLOW_SYMLINKS above already stops a symlinked
                    // *directory* from being recursed into; this is the explicit, belt-and
                    // -braces version covering symlinked files too.
                    if ($file->isLink()) {
                        return false;
                    }

                    return !$file->isDir() || !in_array(
                        strtolower($file->getFilename()),
                        self::PRUNED_DIRECTORY_NAMES,
                        true
                    );
                }
            );

            $iterator = new RecursiveIteratorIterator($filtered, RecursiveIteratorIterator::SELF_FIRST);
            $iterator->setMaxDepth(self::MAX_DEPTH);

            foreach ($iterator as $file) {
                $visited++;
                if ($visited > self::MAX_INODES_VISITED_PER_DIRECTORY) {
                    break;
                }

                if (!$file->isFile()) {
                    continue;
                }

                if (!in_array(strtolower($file->getExtension()), self::EXECUTABLE_EXTENSIONS, true)) {
                    continue;
                }

                $matches[] = [
                    'directory' => $relativeDir,
                    'path' => ltrim(substr($file->getPathname(), strlen($absolutePath)), '/'),
                ];

                if (count($matches) >= self::MAX_MATCHES) {
                    break;
                }
            }
        // phpcs:ignore Magento2.CodeAnalysis.EmptyBlock.DetectedCatch
        } catch (Throwable) {
            // Best-effort - a permission error or similar mid-walk must not fail this reporter
            // or the whole report; whatever was found before the error still counts.
        }

        return $matches;
    }
}
