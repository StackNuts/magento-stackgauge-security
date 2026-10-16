<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Util;

use FilesystemIterator;
use RecursiveCallbackFilterIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use Throwable;

/**
 * Shared bounded, symlink-safe recursive directory walk, used by every scanner that needs to
 * walk part of the local filesystem (PubExecutableScanner, CoreFileTamperScanner,
 * GeneratedCodeScanner). Centralizes the one thing all three needed identically: never follow or
 * even visit a symlink *inside* the tree, cap the depth, and treat any mid-walk error (a
 * permission error, usually) as best-effort rather than a failure - whatever $onEntry already saw
 * still counts, and one unreadable subdirectory only skips that subtree, not the rest of the walk.
 *
 * The scan root itself may be a symlink (Deployer/Capistrano/Hypernode releases routinely symlink
 * pub/media to a shared directory): it is resolved once with realpath() and the walk then runs
 * on the real path. Callers should build relative paths from resolveRoot(), not from the path
 * they passed in. Everything
 * domain-specific - which entries to prune, what counts toward a scanner's own cap, what to do
 * with each file - stays with the caller via $pruneFilter and $onEntry.
 */
class BoundedDirectoryWalker
{
    /**
     * The real (symlink-resolved) path of $absolutePath if it is a readable directory, else null.
     *
     * Only the root is resolved here - symlinks below it are still never followed.
     *
     * @param string $absolutePath
     */
    public function resolveRoot(string $absolutePath): ?string
    {
        // phpcs:ignore Magento2.Functions.DiscouragedFunction.DiscouragedWithAlternative,Magento2.Functions.DiscouragedFunction.Discouraged
        $real = realpath($absolutePath);

        // phpcs:ignore Magento2.Functions.DiscouragedFunction.DiscouragedWithAlternative,Magento2.Functions.DiscouragedFunction.Discouraged
        return $real !== false && is_dir($real) ? rtrim($real, '/') : null;
    }

    /**
     * Walks $absolutePath (resolved once via resolveRoot()) in self-first order, calling $onEntry for every surviving entry.
     *
     * Directories are yielded before their own contents. Symlinks below the root are always
     * excluded, regardless of $pruneFilter. A directory that cannot be opened is skipped without
     * ending the walk.
     *
     * @param string $absolutePath
     * @param int $maxDepth
     * @param callable $pruneFilter function(SplFileInfo $file): bool - return false to exclude
     *     an entry, and for a directory everything beneath it, from the walk.
     * @param callable $onEntry function(SplFileInfo $file): bool - called for every entry that
     *     survives $pruneFilter; return false to stop the walk early, e.g. once a caller's own
     *     cap on matches or visited entries is reached.
     */
    public function walk(string $absolutePath, int $maxDepth, callable $pruneFilter, callable $onEntry): void
    {
        $absolutePath = $this->resolveRoot($absolutePath);
        if ($absolutePath === null) {
            return;
        }

        try {
            $flags = FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS;
            $filtered = new RecursiveCallbackFilterIterator(
                new RecursiveDirectoryIterator($absolutePath, $flags),
                static function (SplFileInfo $file) use ($pruneFilter): bool {
                    // Never descend into (or even report on) a symlink - dev-mode setups commonly
                    // symlink directories back into theme source trees, and following that would
                    // turn a bounded walk into an unbounded one. Omitting
                    // FilesystemIterator::FOLLOW_SYMLINKS above already stops a symlinked
                    // *directory* from being recursed into; this is the explicit, belt-and-braces
                    // version covering symlinked files too.
                    if ($file->isLink()) {
                        return false;
                    }

                    return $pruneFilter($file);
                }
            );

            $iterator = new RecursiveIteratorIterator(
                $filtered,
                RecursiveIteratorIterator::SELF_FIRST,
                RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            $iterator->setMaxDepth($maxDepth);

            foreach ($iterator as $file) {
                if ($onEntry($file) === false) {
                    break;
                }
            }
        // phpcs:ignore Magento2.CodeAnalysis.EmptyBlock.DetectedCatch
        } catch (Throwable) {
            // Best-effort - a permission error or similar mid-walk must not fail the caller;
            // whatever was found before the error still counts.
        }
    }
}
