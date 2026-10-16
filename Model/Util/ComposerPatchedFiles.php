<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Util;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Filesystem;
use Magento\Framework\Filesystem\Directory\ReadInterface;
use Throwable;

/**
 * Which vendor files a composer patch (cweagans/composer-patches or vaimo/composer-patches style)
 * legitimately modified after install, so CoreFileTamperScanner can leave them out instead of
 * reporting every applied hotfix as drift.
 *
 * Sources, all best-effort and read-only:
 * - the project's composer.json `extra.patches` (package => [description => patch file] for
 *   cweagans 1.x/2.x; vaimo-style entries whose value is an array with a `source`/`url`/`path`);
 * - `patches.lock.json` in the project root (cweagans 2.x, package => [{url, depth, ...}]);
 * - `vendor/composer/installed.json` packages' `extra.patches_applied` (cweagans 1.x).
 *
 * Only patch files that exist locally are parsed (remote URLs are not fetched), and only the
 * unified-diff `+++` headers are read, to learn which paths each patch touches (stripping the
 * patch's `depth`, default 1, leading path components). A package whose patches are all remote or
 * unreadable simply contributes no exclusions. This is a minimum viable exclusion, not dist-archive
 * hash verification.
 */
class ComposerPatchedFiles
{
    private const DEFAULT_DEPTH = 1;
    private const MAX_PATCH_BYTES = 2000000;

    /**
     * @var array<string, true>|null "<vendor/package>:<relative path>" => true; memoised per run.
     */
    private ?array $patched = null;

    /**
     * @param Filesystem $filesystem
     * @param SafeFileReader $safeFileReader
     */
    public function __construct(
        private readonly Filesystem $filesystem,
        private readonly SafeFileReader $safeFileReader
    ) {
    }

    /**
     * Whether a patch touches $relativePath inside $package.
     *
     * @param string $package e.g. "magento/framework"
     * @param string $relativePath Path inside the package directory.
     */
    public function isPatched(string $package, string $relativePath): bool
    {
        return isset($this->load()[strtolower($package) . ':' . $relativePath]);
    }

    /**
     * @return array<string, true>
     */
    private function load(): array
    {
        if ($this->patched !== null) {
            return $this->patched;
        }

        $this->patched = [];
        $root = $this->safeFileReader->getDirectoryRead($this->filesystem, DirectoryList::ROOT);
        if ($root === null) {
            return $this->patched;
        }

        foreach ($this->collectPatchEntries($root) as [$package, $location, $depth]) {
            foreach ($this->touchedPaths($root, $location, $depth) as $path) {
                $this->patched[strtolower($package) . ':' . $path] = true;
            }
        }

        return $this->patched;
    }

    /**
     * Every (package, patch location, depth) the project declares or records as applied.
     *
     * @param ReadInterface $root
     * @return list<array{0: string, 1: string, 2: int}>
     */
    private function collectPatchEntries(ReadInterface $root): array
    {
        $entries = [];

        $composer = $this->safeFileReader->readJson($root, 'composer.json');
        $this->addDeclared($entries, $composer['extra']['patches'] ?? null);

        $lock = $this->safeFileReader->readJson($root, 'patches.lock.json');
        $this->addDeclared($entries, $lock['patches'] ?? null);

        $installed = $this->safeFileReader->readJson($root, 'vendor/composer/installed.json');
        $packages = $installed['packages'] ?? $installed;
        if (is_array($packages)) {
            foreach ($packages as $package) {
                if (is_array($package) && is_string($package['name'] ?? null)) {
                    $this->addDeclared(
                        $entries,
                        [$package['name'] => $package['extra']['patches_applied'] ?? null]
                    );
                }
            }
        }

        return $entries;
    }

    /**
     * Adds entries from a `package => patches` map in any of the shapes listed in the class docblock.
     *
     * @param list<array{0: string, 1: string, 2: int}> $entries
     * @param mixed $map
     */
    private function addDeclared(array &$entries, mixed $map): void
    {
        if (!is_array($map)) {
            return;
        }

        foreach ($map as $package => $patches) {
            if (!is_string($package) || !is_array($patches)) {
                continue;
            }

            foreach ($patches as $patch) {
                $location = $patch;
                $depth = self::DEFAULT_DEPTH;
                if (is_array($patch)) {
                    $location = $patch['url'] ?? $patch['source'] ?? $patch['path'] ?? null;
                    $depth = is_int($patch['depth'] ?? null) ? $patch['depth'] : self::DEFAULT_DEPTH;
                }

                if (is_string($location) && $location !== '' && !preg_match('#^[a-z][a-z0-9+.-]*://#i', $location)) {
                    $entries[] = [$package, ltrim($location, '/'), $depth];
                }
            }
        }
    }

    /**
     * The package-relative paths a local unified diff modifies.
     *
     * @param ReadInterface $root
     * @param string $location Patch file path relative to the project root.
     * @param int $depth Leading path components to strip (`patch -pN`).
     * @return list<string>
     */
    private function touchedPaths(ReadInterface $root, string $location, int $depth): array
    {
        if (str_contains($location, '..')) {
            return [];
        }

        try {
            if (!$root->isFile($location) || $root->stat($location)['size'] > self::MAX_PATCH_BYTES) {
                return [];
            }
            $content = $root->readFile($location);
        } catch (Throwable) {
            return [];
        }

        $paths = [];
        foreach (preg_split('/\R/', $content) ?: [] as $line) {
            if (!str_starts_with($line, '+++ ')) {
                continue;
            }

            $path = trim(explode("\t", substr($line, 4))[0]);
            if ($path === '' || $path === '/dev/null') {
                continue;
            }

            $parts = explode('/', $path);
            $path = implode('/', array_slice($parts, $depth));
            if ($path !== '') {
                $paths[] = $path;
            }
        }

        return $paths;
    }
}
