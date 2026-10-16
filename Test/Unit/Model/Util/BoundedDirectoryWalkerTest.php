<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Test\Unit\Model\Util;

use PHPUnit\Framework\TestCase;
use SplFileInfo;
use StackNuts\StackGaugeSecurity\Model\Util\BoundedDirectoryWalker;

/**
 * Real temporary directory trees, not mocks - symlink and permission behaviour is the point.
 */
class BoundedDirectoryWalkerTest extends TestCase
{
    private string $base;

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir() . '/sg-walker-' . uniqid('', true);
        mkdir($this->base, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->remove($this->base);
    }

    private function remove(string $path): void
    {
        if (is_link($path) || is_file($path)) {
            unlink($path);
            return;
        }
        if (!is_dir($path)) {
            return;
        }
        chmod($path, 0777);
        foreach (scandir($path) ?: [] as $entry) {
            if ($entry !== '.' && $entry !== '..') {
                $this->remove($path . '/' . $entry);
            }
        }
        rmdir($path);
    }

    /**
     * @return list<string> Paths relative to $root, sorted.
     */
    private function collect(string $root, int $depth = 8, ?callable $prune = null): array
    {
        $seen = [];
        (new BoundedDirectoryWalker())->walk(
            $root,
            $depth,
            $prune ?? static fn (SplFileInfo $file): bool => true,
            function (SplFileInfo $file) use (&$seen, $root): bool {
                $real = (string)realpath($root);
                $seen[] = ltrim(substr($file->getPathname(), strlen($real)), '/');
                return true;
            }
        );
        sort($seen);

        return $seen;
    }

    public function testWalksFilesAndDirectories(): void
    {
        mkdir($this->base . '/a/b', 0777, true);
        touch($this->base . '/a/b/x.php');

        $this->assertSame(['a', 'a/b', 'a/b/x.php'], $this->collect($this->base));
    }

    public function testWalksASymlinkedScanRoot(): void
    {
        mkdir($this->base . '/shared/media', 0777, true);
        touch($this->base . '/shared/media/shell.php');
        mkdir($this->base . '/release/pub', 0777, true);
        symlink($this->base . '/shared/media', $this->base . '/release/pub/media');

        $walker = new BoundedDirectoryWalker();
        $this->assertSame(
            realpath($this->base . '/shared/media'),
            $walker->resolveRoot($this->base . '/release/pub/media')
        );
        $this->assertSame(['shell.php'], $this->collect($this->base . '/release/pub/media'));
    }

    public function testStillNeverFollowsSymlinksInsideTheTree(): void
    {
        mkdir($this->base . '/root', 0777, true);
        mkdir($this->base . '/outside', 0777, true);
        touch($this->base . '/outside/evil.php');
        symlink($this->base . '/outside', $this->base . '/root/linked-dir');
        symlink($this->base . '/outside/evil.php', $this->base . '/root/linked-file.php');
        touch($this->base . '/root/ok.php');

        $this->assertSame(['ok.php'], $this->collect($this->base . '/root'));
    }

    public function testMissingOrNonDirectoryRootWalksNothing(): void
    {
        touch($this->base . '/file');

        $walker = new BoundedDirectoryWalker();
        $this->assertNull($walker->resolveRoot($this->base . '/nope'));
        $this->assertNull($walker->resolveRoot($this->base . '/file'));
        $this->assertSame([], $this->collect($this->base . '/nope'));
    }

    public function testAnUnreadableSubdirectoryDoesNotEndTheWalk(): void
    {
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            $this->markTestSkipped('chmod 000 does not stop root from reading.');
        }

        // "a-locked" sorts/reads first in many filesystems, but order is not guaranteed - plant
        // readable siblings on both sides of it.
        foreach (['0-before', 'a-locked', 'z-after'] as $dir) {
            mkdir($this->base . '/' . $dir, 0777, true);
            touch($this->base . '/' . $dir . '/file.php');
        }
        chmod($this->base . '/a-locked', 0000);

        $seen = $this->collect($this->base);

        $this->assertContains('0-before/file.php', $seen);
        $this->assertContains('z-after/file.php', $seen);
        $this->assertContains('a-locked', $seen);
        $this->assertNotContains('a-locked/file.php', $seen);
    }

    public function testRespectsMaxDepthAndPruneFilter(): void
    {
        mkdir($this->base . '/a/b/c', 0777, true);
        mkdir($this->base . '/skip', 0777, true);
        touch($this->base . '/a/b/c/deep.php');
        touch($this->base . '/skip/hidden.php');

        $seen = $this->collect(
            $this->base,
            1,
            static fn (SplFileInfo $file): bool => $file->getFilename() !== 'skip'
        );

        $this->assertSame(['a', 'a/b'], $seen);
    }

    public function testStopsWhenTheCallbackReturnsFalse(): void
    {
        touch($this->base . '/one.php');
        touch($this->base . '/two.php');
        $count = 0;

        (new BoundedDirectoryWalker())->walk(
            $this->base,
            3,
            static fn (SplFileInfo $file): bool => true,
            function () use (&$count): bool {
                $count++;
                return false;
            }
        );

        $this->assertSame(1, $count);
    }
}
