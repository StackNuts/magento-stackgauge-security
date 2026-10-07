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
 * Matches "generated_php" signatures against the PHP that Magento compiles into generated/code/
 * (interceptors, proxies, factories). Attackers persist here because the files are regenerated
 * rarely and rarely reviewed, so a backdoor injected into an interceptor survives a cache flush.
 *
 * Each file is read, matched, and discarded in turn rather than collected first, so peak memory
 * stays at one file regardless of how large generated/code grows. The walk is bounded the same
 * way PubExecutableScanner's is: no symlinks, a maximum depth, a file-count cap, and a per-file
 * size cap. Reaching the file cap sets $truncated so the dashboard shows the scan was incomplete
 * rather than silently partial.
 */
class GeneratedCodeScanner
{
    private const MAX_FILES = 20000;
    private const MAX_DEPTH = 16;
    private const MAX_FILE_BYTES = 2000000;

    /**
     * @param Filesystem $filesystem
     * @param ContentSignatureScanner $scanner
     * @param SafeFileReader $safeFileReader
     * @param BoundedDirectoryWalker $walker
     */
    public function __construct(
        private readonly Filesystem $filesystem,
        private readonly ContentSignatureScanner $scanner,
        private readonly SafeFileReader $safeFileReader,
        private readonly BoundedDirectoryWalker $walker
    ) {
    }

    /**
     * @param list<array<string, mixed>> $signatures
     * @return array{matches: list<array>, truncated: bool}
     */
    public function scan(array $signatures): array
    {
        $matches = [];
        $truncated = false;

        $root = $this->safeFileReader->resolveAbsolutePath($this->filesystem, DirectoryList::ROOT, 'generated/code');
        if ($root === null) {
            return ['matches' => [], 'truncated' => false];
        }

        $visited = 0;
        $this->walker->walk(
            $root,
            self::MAX_DEPTH,
            static fn (SplFileInfo $file): bool => true,
            function (SplFileInfo $file) use (&$matches, &$visited, &$truncated, $root, $signatures): bool {
                if (!$file->isFile() || strtolower($file->getExtension()) !== 'php') {
                    return true;
                }

                if (++$visited > self::MAX_FILES) {
                    $truncated = true;
                    return false;
                }

                if ($file->getSize() > self::MAX_FILE_BYTES) {
                    return true;
                }

                $content = (string)file_get_contents($file->getPathname());
                $relative = ltrim(substr($file->getPathname(), strlen($root)), '/');
                foreach ($this->scanner->scan($signatures, 'generated_php', ['generated/code/' . $relative => $content]) as $match) {
                    $matches[] = $match;
                }

                return true;
            }
        );

        return ['matches' => $matches, 'truncated' => $truncated];
    }
}
