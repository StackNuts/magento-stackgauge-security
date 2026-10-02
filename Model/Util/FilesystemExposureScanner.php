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
 * Shallow (non-recursive) checks for things that shouldn't exist in the webroot at all - VCS
 * metadata, leftover backup/dump files, and PHP files in pub/ outside Magento's own known
 * entrypoints. Only ever lists the project root's and pub/'s own top-level contents - this
 * deliberately never walks into a subdirectory, so it's cheap regardless of how large the
 * install is. A bounded *recursive* walk of pub/media and pub/static specifically is a
 * separate, harder problem - see Model\Util\PubExecutableScanner.
 *
 * Findings are split by location (root vs pub/) because they carry different weight: a file
 * reachable under pub/ is reachable right now, full stop, since pub/ is the real docroot on
 * every correctly-deployed Magento install. The same file sitting in the project root is only
 * reachable if the docroot is misconfigured to point there instead - still worth knowing
 * about, but a different (lesser, conditional) risk, which is why this reports both rather
 * than only checking pub/.
 */
class FilesystemExposureScanner
{
    /**
     * @var list<string>
     */
    private const VCS_DIRECTORIES = ['.git', '.svn', '.hg', '.bzr'];

    /**
     * @var list<string>
     */
    private const BACKUP_EXTENSIONS = ['sql', 'bak', 'old', 'zip', 'tar', 'gz', 'tgz'];

    /**
     * Magento's own pub/ entrypoints - anything else is unexpected. errors/*.php (the default
     * error-page templates) live in their own subdirectory, so they never show up in a
     * top-level listing of pub/ at all and don't need to be allow-listed here.
     *
     * @var list<string>
     */
    private const KNOWN_PUB_PHP_FILES = ['index.php', 'cron.php', 'get.php', 'health_check.php', 'static.php'];

    /**
     * @param Filesystem $filesystem
     */
    public function __construct(private readonly Filesystem $filesystem)
    {
    }

    /**
     * Scans the project root and pub/ for exposure findings.
     *
     * @return list<array{location: string, type: string, name: string}>
     */
    public function scan(): array
    {
        try {
            $rootDir = $this->filesystem->getDirectoryRead(DirectoryList::ROOT);
            $pubDir = $this->filesystem->getDirectoryRead(DirectoryList::PUB);

            return [
                ...$this->findingsFor($rootDir, 'root'),
                ...$this->findingsFor($pubDir, 'pub'),
                ...array_map(
                    fn (string $name) => ['location' => 'pub', 'type' => 'unrecognized_php_file', 'name' => $name],
                    $this->findUnrecognizedPhpFiles($pubDir)
                ),
            ];
        } catch (Throwable) {
            // Best-effort - an unreadable directory must not fail this reporter or the whole report.
            return [];
        }
    }

    /**
     * VCS directories and backup files found directly under $dir, tagged with $location.
     *
     * @param ReadInterface $dir
     * @param string $location
     * @return list<array{location: string, type: string, name: string}>
     */
    private function findingsFor(ReadInterface $dir, string $location): array
    {
        $findings = [];

        foreach (self::VCS_DIRECTORIES as $name) {
            if ($dir->isExist($name) && $dir->isDirectory($name)) {
                $findings[] = ['location' => $location, 'type' => 'vcs_directory', 'name' => $name];
            }
        }

        foreach ($this->findBackupFiles($dir) as $name) {
            $findings[] = ['location' => $location, 'type' => 'backup_file', 'name' => $name];
        }

        return $findings;
    }

    /**
     * Top-level files in $dir matching BACKUP_EXTENSIONS.
     *
     * @param ReadInterface $dir
     * @return list<string>
     */
    private function findBackupFiles(ReadInterface $dir): array
    {
        $matches = [];

        foreach ($dir->read() as $entry) {
            if ($dir->isDirectory($entry)) {
                continue;
            }

            // phpcs:ignore Magento2.Functions.DiscouragedFunction.DiscouragedWithAlternative
            $extension = strtolower((string)pathinfo($entry, PATHINFO_EXTENSION));
            if (in_array($extension, self::BACKUP_EXTENSIONS, true)) {
                $matches[] = $entry;
            }
        }

        return $matches;
    }

    /**
     * Top-level .php files in pub/ that aren't in KNOWN_PUB_PHP_FILES.
     *
     * @param ReadInterface $pubDir
     * @return list<string>
     */
    private function findUnrecognizedPhpFiles(ReadInterface $pubDir): array
    {
        $matches = [];

        foreach ($pubDir->read() as $entry) {
            if ($pubDir->isDirectory($entry)) {
                continue;
            }

            // phpcs:ignore Magento2.Functions.DiscouragedFunction.DiscouragedWithAlternative
            $extension = strtolower((string)pathinfo($entry, PATHINFO_EXTENSION));
            if ($extension === 'php' && !in_array($entry, self::KNOWN_PUB_PHP_FILES, true)) {
                $matches[] = $entry;
            }
        }

        return $matches;
    }
}
