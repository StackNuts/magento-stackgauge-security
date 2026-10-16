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
use StackNuts\StackGaugeSecurity\Model\Util\SafeFileReader;

class SafeFileReaderTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/sg-safereader-' . uniqid('', true);
        mkdir($this->dir, 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->dir);
    }

    /**
     * A ReadInterface backed by real files in $this->dir.
     */
    private function directory(): ReadInterface
    {
        $directory = $this->createStub(ReadInterface::class);
        $directory->method('isExist')->willReturnCallback(fn (string $path): bool => file_exists($this->dir . '/' . $path));
        $directory->method('readFile')->willReturnCallback(function (string $path): string {
            $content = file_get_contents($this->dir . '/' . $path);
            if ($content === false) {
                throw new RuntimeException('unreadable');
            }

            return $content;
        });
        $directory->method('getAbsolutePath')->willReturnCallback(fn (string $path): string => $this->dir . '/' . $path);

        return $directory;
    }

    public function testReadJsonDecodesAnObject(): void
    {
        file_put_contents($this->dir . '/a.json', '{"k": [1, 2]}');

        $this->assertSame(['k' => [1, 2]], (new SafeFileReader(new Json()))->readJson($this->directory(), 'a.json'));
    }

    public function testReadJsonReturnsNullForMissingMalformedOrScalarContent(): void
    {
        file_put_contents($this->dir . '/bad.json', '{not json');
        file_put_contents($this->dir . '/scalar.json', '"just a string"');
        $reader = new SafeFileReader(new Json());

        $this->assertNull($reader->readJson($this->directory(), 'missing.json'));
        $this->assertNull($reader->readJson($this->directory(), 'bad.json'));
        $this->assertNull($reader->readJson($this->directory(), 'scalar.json'));
    }

    public function testReadRawReturnsExactBytesOrNull(): void
    {
        file_put_contents($this->dir . '/raw', "line1\n  line2 \n");
        $reader = new SafeFileReader(new Json());

        $this->assertSame("line1\n  line2 \n", $reader->readRaw($this->directory(), 'raw'));
        $this->assertNull($reader->readRaw($this->directory(), 'missing'));
    }

    public function testReadRawAndReadJsonSwallowReadErrors(): void
    {
        $directory = $this->createStub(ReadInterface::class);
        $directory->method('isExist')->willReturn(true);
        $directory->method('readFile')->willThrowException(new RuntimeException('boom'));
        $reader = new SafeFileReader(new Json());

        $this->assertNull($reader->readRaw($directory, 'x'));
        $this->assertNull($reader->readJson($directory, 'x'));
    }

    public function testGetDirectoryReadAndResolveAbsolutePath(): void
    {
        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willReturn($this->directory());
        $reader = new SafeFileReader(new Json());

        $this->assertNotNull($reader->getDirectoryRead($filesystem, 'root'));
        $this->assertSame($this->dir . '/pub', $reader->resolveAbsolutePath($filesystem, 'root', 'pub'));
    }

    public function testDirectoryLookupFailuresReturnNull(): void
    {
        $filesystem = $this->createStub(Filesystem::class);
        $filesystem->method('getDirectoryRead')->willThrowException(new RuntimeException('no such code'));
        $reader = new SafeFileReader(new Json());

        $this->assertNull($reader->getDirectoryRead($filesystem, 'nope'));
        $this->assertNull($reader->resolveAbsolutePath($filesystem, 'nope', 'pub'));

        $throwing = $this->createStub(ReadInterface::class);
        $throwing->method('getAbsolutePath')->willThrowException(new RuntimeException('bad path'));
        $filesystem2 = $this->createStub(Filesystem::class);
        $filesystem2->method('getDirectoryRead')->willReturn($throwing);

        $this->assertNull($reader->resolveAbsolutePath($filesystem2, 'root', 'pub'));
    }
}
