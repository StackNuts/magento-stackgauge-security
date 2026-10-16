<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Test\Unit\Model\Util;

use Magento\Framework\Filesystem;
use Magento\Framework\Filesystem\Directory\ReadInterface;
use Magento\Framework\Serialize\Serializer\Json;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use StackNuts\StackGaugeSecurity\Model\Util\PubFileContentReader;
use StackNuts\StackGaugeSecurity\Model\Util\SafeFileReader;

class PubFileContentReaderTest extends TestCase
{
    public function testReadsContentOfEachMatchedFile(): void
    {
        $root = $this->createStub(ReadInterface::class);
        $root->method('isExist')->willReturn(true);
        $root->method('stat')->willReturn(['size' => 100]);
        $root->method('readFile')->willReturn('<?php eval($_POST[1]); ?>');

        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willReturn($root);

        $reader = new PubFileContentReader($filesystem, new SafeFileReader(new Json()));
        $content = $reader->readContents([['directory' => 'pub/media', 'path' => 'shell.php']]);

        $this->assertSame(['pub_file:pub/media/shell.php' => '<?php eval($_POST[1]); ?>'], $content);
    }

    public function testSkipsFilesLargerThanTheByteCap(): void
    {
        $root = $this->createStub(ReadInterface::class);
        $root->method('isExist')->willReturn(true);
        $root->method('stat')->willReturn(['size' => 3_000_000]);

        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willReturn($root);

        $reader = new PubFileContentReader($filesystem, new SafeFileReader(new Json()));
        $content = $reader->readContents([['directory' => 'pub/media', 'path' => 'huge.php']]);

        $this->assertSame([], $content);
    }

    public function testSkipsAFileThatNoLongerExists(): void
    {
        $root = $this->createStub(ReadInterface::class);
        $root->method('isExist')->willReturn(false);

        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willReturn($root);

        $reader = new PubFileContentReader($filesystem, new SafeFileReader(new Json()));
        $content = $reader->readContents([['directory' => 'pub/media', 'path' => 'gone.php']]);

        $this->assertSame([], $content);
    }

    public function testReturnsEmptyArrayWhenFilesystemThrows(): void
    {
        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willThrowException(new RuntimeException('boom'));

        $reader = new PubFileContentReader($filesystem, new SafeFileReader(new Json()));

        $this->assertSame([], $reader->readContents([['directory' => 'pub/media', 'path' => 'shell.php']]));
    }

    /**
     * A ReadInterface over real files under $base, so size caps and reads are genuine.
     */
    private function realFilesystem(string $base): Filesystem
    {
        $root = $this->createStub(ReadInterface::class);
        $root->method('isExist')->willReturnCallback(static fn (string $p): bool => file_exists($base . '/' . $p));
        $root->method('stat')->willReturnCallback(static function (string $p) use ($base): array {
            if (str_contains($p, 'unstatable')) {
                throw new RuntimeException('stat failed');
            }

            return ['size' => (int)filesize($base . '/' . $p)];
        });
        $root->method('readFile')->willReturnCallback(static fn (string $p): string => (string)file_get_contents($base . '/' . $p));
        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willReturn($root);

        return $filesystem;
    }

    public function testReadsRealFilesSkipsOversizedAndKeepsGoingAfterAnUnreadableOne(): void
    {
        $base = sys_get_temp_dir() . '/sg-pubreader-' . uniqid('', true);
        mkdir($base . '/pub/media/wysiwyg', 0777, true);
        file_put_contents($base . '/pub/media/wysiwyg/shell.php', '<?php eval($_POST[1]);');
        file_put_contents($base . '/pub/media/unstatable.php', 'x');
        file_put_contents($base . '/pub/media/huge.php', str_repeat('A', 2_000_001));
        file_put_contents($base . '/pub/media/exactly-cap.php', str_repeat('A', 2_000_000));

        try {
            $reader = new PubFileContentReader($this->realFilesystem($base), new SafeFileReader(new Json()));
            $content = $reader->readContents([
                ['directory' => 'pub/media', 'path' => 'unstatable.php'],
                ['directory' => 'pub/media', 'path' => 'huge.php'],
                ['directory' => 'pub/media/', 'path' => '/wysiwyg/shell.php'],
                ['directory' => 'pub/media', 'path' => 'exactly-cap.php'],
                ['directory' => 'pub/media', 'path' => 'gone.php'],
            ]);

            $this->assertSame(
                ['pub_file:pub/media/wysiwyg/shell.php', 'pub_file:pub/media/exactly-cap.php'],
                array_keys($content)
            );
            $this->assertSame('<?php eval($_POST[1]);', $content['pub_file:pub/media/wysiwyg/shell.php']);
        } finally {
            foreach (glob($base . '/pub/media/*.php') ?: [] as $f) {
                unlink($f);
            }
            unlink($base . '/pub/media/wysiwyg/shell.php');
            rmdir($base . '/pub/media/wysiwyg');
            rmdir($base . '/pub/media');
            rmdir($base . '/pub');
            rmdir($base);
        }
    }

    public function testReadsThroughASymlinkedMediaDirectory(): void
    {
        $base = sys_get_temp_dir() . '/sg-pubreader-' . uniqid('', true);
        mkdir($base . '/shared', 0777, true);
        mkdir($base . '/pub', 0777, true);
        file_put_contents($base . '/shared/shell.php', 'payload');
        symlink($base . '/shared', $base . '/pub/media');

        try {
            $reader = new PubFileContentReader($this->realFilesystem($base), new SafeFileReader(new Json()));
            $content = $reader->readContents([['directory' => 'pub/media', 'path' => 'shell.php']]);

            $this->assertSame(['pub_file:pub/media/shell.php' => 'payload'], $content);
        } finally {
            unlink($base . '/pub/media');
            unlink($base . '/shared/shell.php');
            rmdir($base . '/shared');
            rmdir($base . '/pub');
            rmdir($base);
        }
    }
}
