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
 * hard cap on entries visited per walk (not just matches), a max depth, never follows symlinks
 * below the scan root (common in dev-mode setups, which would otherwise risk loops or turn this
 * into scanning the entire theme source tree - the root itself may be a symlink, as
 * Deployer/Capistrano setups symlink pub/media), and prunes the one known-huge,
 * categorically-image-only directory (pub/media/catalog/product/cache, matched by path, not by
 * name) before ever descending into it. Directories where a webshell is most likely to be
 * dropped (tmp, custom_options, customer_address, wysiwyg, import, downloadable) are walked first
 * with their own budget, so an arbitrary readdir order over a huge catalog can't starve them.
 * Hitting any budget sets wasTruncated() so the dashboard can show the scan was partial.
 *
 * This walks the local filesystem directly via SPL iterators rather than through Magento's own
 * Filesystem\DriverInterface abstraction - simpler and faster for a plain bounded local walk,
 * but it means a store using a remote/cloud media storage driver gets a scan that silently
 * finds nothing rather than an error. Treat a clean result from this scanner as "nothing found
 * on local disk", not an absolute guarantee.
 */
class PubExecutableScanner
{
    private const MAX_INODES_VISITED_PER_WALK = 5000;
    private const MAX_DEPTH = 8;
    private const MAX_MATCHES = 80;

    /**
     * @var list<string>
     */
    private const SCAN_DIRECTORIES = ['pub/media', 'pub/static'];

    /**
     * Subdirectories of pub/media walked first, each with its own budget - the usual upload and
     * import drop locations for a webshell.
     *
     * @var array<string, list<string>>
     */
    private const PRIORITY_DIRECTORIES = [
        'pub/media' => ['tmp', 'custom_options', 'customer_address', 'wysiwyg', 'import', 'downloadable'],
    ];

    /**
     * Paths (relative to the scan root, lower-case) pruned before descending - large and
     * categorically image-only.
     *
     * @var list<string>
     */
    private const PRUNED_RELATIVE_PATHS = ['catalog/product/cache'];

    /**
     * @var list<string>
     */
    private const EXECUTABLE_EXTENSIONS = [
        'php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7', 'phps', 'pht', 'phtm', 'inc',
    ];

    /**
     * Config files that make a "static" directory execute code or change how it is served.
     *
     * @var list<string>
     */
    private const SUSPICIOUS_FILENAMES = ['.user.ini'];

    /**
     * @var list<array{directory: string, path: string}>|null Memoised scan() result - both
     *     SecurityReporter and ContentSignatureReporter ask for it in the same run.
     */
    private ?array $result = null;

    private bool $truncated = false;

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
     * Scans pub/media and pub/static for unexpected executable-extension files. Memoised per
     * instance (one run).
     *
     * @return list<array{directory: string, path: string}>
     */
    public function scan(): array
    {
        if ($this->result !== null) {
            return $this->result;
        }

        $matches = [];

        foreach (self::SCAN_DIRECTORIES as $relativeDir) {
            foreach ($this->scanDirectory($relativeDir) as $match) {
                $matches[] = $match;
                if (count($matches) >= self::MAX_MATCHES) {
                    return $this->result = $matches;
                }
            }
        }

        return $this->result = $matches;
    }

    /**
     * Whether any walk in the last scan() stopped at its entry budget, so the result may be
     * incomplete.
     */
    public function wasTruncated(): bool
    {
        $this->scan();

        return $this->truncated;
    }

    /**
     * Bounded scan of one directory - priority drop locations first, then the rest. See this
     * class's own docblock for the safety bounds.
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
        $absolutePath = $absolutePath === null ? null : $this->walker->resolveRoot($absolutePath);
        if ($absolutePath === null) {
            return [];
        }

        $matches = [];
        $priority = self::PRIORITY_DIRECTORIES[$relativeDir] ?? [];

        foreach ($priority as $subDirectory) {
            $this->walk($relativeDir, $absolutePath, $subDirectory, $matches, []);
        }

        $this->walk($relativeDir, $absolutePath, '', $matches, $priority);

        return array_slice($matches, 0, self::MAX_MATCHES);
    }

    /**
     * One budgeted walk of $absolutePath/$subDirectory, appending to $matches.
     *
     * @param string $relativeDir
     * @param string $absolutePath Resolved scan root.
     * @param string $subDirectory Relative to the scan root; '' for the root itself.
     * @param array $matches
     * @param list<string> $skipTopLevel Top-level names already covered by a priority walk.
     */
    private function walk(
        string $relativeDir,
        string $absolutePath,
        string $subDirectory,
        array &$matches,
        array $skipTopLevel
    ): void {
        $start = $subDirectory === '' ? $absolutePath : $absolutePath . '/' . $subDirectory;
        $visited = 0;

        $this->walker->walk(
            $start,
            self::MAX_DEPTH,
            static function (SplFileInfo $file) use ($absolutePath, $skipTopLevel): bool {
                if (!$file->isDir()) {
                    return true;
                }
                $relative = strtolower(ltrim(substr($file->getPathname(), strlen($absolutePath)), '/'));

                return !in_array($relative, self::PRUNED_RELATIVE_PATHS, true)
                    && !in_array($relative, $skipTopLevel, true);
            },
            function (SplFileInfo $file) use (&$matches, &$visited, $relativeDir, $absolutePath): bool {
                if (++$visited > self::MAX_INODES_VISITED_PER_WALK) {
                    $this->truncated = true;
                    return false;
                }

                if (!$file->isFile()) {
                    return true;
                }

                $isExecutable = in_array(strtolower($file->getExtension()), self::EXECUTABLE_EXTENSIONS, true)
                    || in_array(strtolower($file->getFilename()), self::SUSPICIOUS_FILENAMES, true);
                if (!$isExecutable) {
                    return true;
                }

                $matches[] = [
                    'directory' => $relativeDir,
                    'path' => ltrim(substr($file->getPathname(), strlen($absolutePath)), '/'),
                ];

                return count($matches) < self::MAX_MATCHES;
            }
        );
    }
}
