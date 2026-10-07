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
 * Heuristic core-file tamper check: flags PHP files under vendor/magento/* and vendor/mage-os/*
 * whose mtime drifts anomalously newer than the rest of their own package's files. A
 * `composer install` writes every file in a package at roughly the same time, so one file
 * sitting days newer than its own package siblings is a signal something touched it directly
 * after the fact - a hotfix hand-applied to a live server instead of through a proper
 * patch/release, or something worse.
 *
 * This is a soft heuristic, not a real integrity check, and that limitation belongs here in
 * the open, not just in a code comment: a `touch -r` call (or any deploy process that resets
 * mtimes uniformly) defeats it trivially. It catches casual or accidental tampering, not a
 * determined attacker who thought to cover their tracks. A proper version would hash every
 * vendor file against a known-good manifest, which Composer doesn't provide by default and is
 * a meaningfully bigger feature than this one.
 *
 * Bounded per-package (a cap on files inspected within one package, with the same
 * never-follow-symlinks, no-deep-recursion discipline as PubExecutableScanner) and in
 * aggregate (a cap on total files inspected across every package in one run) - this store
 * alone has ~30,000 PHP files across ~380 packages under vendor/mage-os; a larger Commerce
 * install can have meaningfully more. Hitting the aggregate cap mid-run means a partial
 * result, not a failure - whatever was checked before stopping still counts.
 */
class CoreFileTamperScanner
{
    /**
     * @var list<string>
     */
    private const VENDOR_PREFIXES = ['magento', 'mage-os'];

    private const DRIFT_THRESHOLD_SECONDS = 172800; // 48 hours
    private const MAX_FILES_PER_PACKAGE = 2000;
    private const MAX_TOTAL_FILES_VISITED = 50000;
    private const MAX_DEPTH = 10;
    private const MAX_MATCHES = 80;

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
     * Scans vendor/magento/* and vendor/mage-os/* for anomalous mtime drift.
     *
     * @return list<array{package: string, path: string, drift_hours: int}>
     */
    public function scan(): array
    {
        $vendorRoot = $this->safeFileReader->resolveAbsolutePath($this->filesystem, DirectoryList::ROOT, 'vendor');
        if ($vendorRoot === null) {
            return [];
        }
        $vendorRoot = rtrim($vendorRoot, '/');

        $matches = [];
        $totalVisited = 0;

        foreach (self::VENDOR_PREFIXES as $vendorPrefix) {
            $prefixPath = $vendorRoot . '/' . $vendorPrefix;
            // phpcs:ignore Magento2.Functions.DiscouragedFunction.DiscouragedWithAlternative,Magento2.Functions.DiscouragedFunction.Discouraged
            if (!is_dir($prefixPath) || is_link($prefixPath)) {
                continue;
            }

            foreach ($this->listPackageDirectories($prefixPath) as $packageName => $packagePath) {
                [$packageMatches, $visited] = $this->scanPackage("{$vendorPrefix}/{$packageName}", $packagePath);
                $matches = [...$matches, ...$packageMatches];
                $totalVisited += $visited;

                if (count($matches) >= self::MAX_MATCHES || $totalVisited >= self::MAX_TOTAL_FILES_VISITED) {
                    return array_slice($matches, 0, self::MAX_MATCHES);
                }
            }
        }

        return $matches;
    }

    /**
     * Lists the immediate package subdirectories of one vendor prefix (e.g. vendor/magento).
     *
     * @param string $prefixPath
     * @return array<string, string> package name => absolute path
     */
    private function listPackageDirectories(string $prefixPath): array
    {
        $packages = [];

        // phpcs:ignore Magento2.Functions.DiscouragedFunction.Discouraged
        foreach ((scandir($prefixPath) ?: []) as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $path = $prefixPath . '/' . $entry;
            // phpcs:ignore Magento2.Functions.DiscouragedFunction.DiscouragedWithAlternative,Magento2.Functions.DiscouragedFunction.Discouraged
            if (is_dir($path) && !is_link($path)) {
                $packages[$entry] = $path;
            }
        }

        return $packages;
    }

    /**
     * Bounded scan of one package's PHP file mtimes for anomalous drift.
     *
     * Collects .php file mtimes within one package (bounded by MAX_FILES_PER_PACKAGE), then
     * flags any whose drift from the package's own median mtime exceeds DRIFT_THRESHOLD_SECONDS.
     *
     * @param string $packageLabel
     * @param string $packagePath
     * @return array{0: list<array{package: string, path: string, drift_hours: int}>, 1: int}
     */
    private function scanPackage(string $packageLabel, string $packagePath): array
    {
        $mtimesByPath = [];

        $this->walker->walk(
            $packagePath,
            self::MAX_DEPTH,
            static fn (SplFileInfo $file): bool => true,
            function (SplFileInfo $file) use (&$mtimesByPath, $packagePath): bool {
                if (count($mtimesByPath) >= self::MAX_FILES_PER_PACKAGE) {
                    return false;
                }

                if (!$file->isFile() || strtolower($file->getExtension()) !== 'php') {
                    return true;
                }

                $mtime = $file->getMTime();
                if ($mtime !== false) {
                    $relativePath = ltrim(substr($file->getPathname(), strlen($packagePath)), '/');
                    $mtimesByPath[$relativePath] = $mtime;
                }

                return true;
            }
        );

        if (count($mtimesByPath) < 2) {
            // Nothing to compare against - a single-file (or empty) package has no "the rest
            // of the package" baseline to drift from.
            return [[], count($mtimesByPath)];
        }

        $median = $this->median(array_values($mtimesByPath));
        $matches = [];

        foreach ($mtimesByPath as $relativePath => $mtime) {
            $driftSeconds = $mtime - $median;
            if ($driftSeconds > self::DRIFT_THRESHOLD_SECONDS) {
                $matches[] = [
                    'package' => $packageLabel,
                    'path' => $relativePath,
                    'drift_hours' => (int)round($driftSeconds / 3600),
                ];
            }
        }

        return [$matches, count($mtimesByPath)];
    }

    /**
     * The median of $values.
     *
     * @param list<int> $values
     */
    private function median(array $values): float
    {
        sort($values);
        $count = count($values);
        $middle = intdiv($count, 2);

        if ($count % 2 === 0) {
            return ($values[$middle - 1] + $values[$middle]) / 2;
        }

        return (float)$values[$middle];
    }
}
