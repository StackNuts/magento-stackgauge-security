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
}
