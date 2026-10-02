<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Test\Unit\Model\ContentSource;

use Magento\Framework\App\ResourceConnection;
use Magento\Framework\DB\Adapter\AdapterInterface;
use Magento\Framework\DB\Select;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use StackNuts\StackGaugeSecurity\Model\ContentSource\DesignConfigContentSource;

class DesignConfigContentSourceTest extends TestCase
{
    /**
     * @param list<array<string, mixed>> $rows
     */
    private function source(array $rows): DesignConfigContentSource
    {
        $select = $this->createMock(Select::class);
        $select->method('from')->willReturn($select);
        $select->method('where')->willReturn($select);

        $connection = $this->createMock(AdapterInterface::class);
        $connection->method('select')->willReturn($select);
        $connection->method('quoteInto')->willReturn('path IN (...)');
        $connection->method('fetchAll')->willReturn($rows);

        $resourceConnection = $this->createStub(ResourceConnection::class);
        $resourceConnection->method('getConnection')->willReturn($connection);
        $resourceConnection->method('getTableName')->willReturnArgument(0);

        return new DesignConfigContentSource($resourceConnection);
    }

    public function testGetContentReturnsEmptyArrayWhenNoRowsMatch(): void
    {
        $this->assertSame([], $this->source([])->getContent());
    }

    public function testGetContentKeysEachRowByPathScopeAndScopeId(): void
    {
        $source = $this->source([
            [
                'scope' => 'default',
                'scope_id' => 0,
                'path' => 'design/head/includes',
                'value' => '<script src="legit.js"></script>',
            ],
        ]);

        $this->assertSame(
            ['design_config:design/head/includes:default:0' => '<script src="legit.js"></script>'],
            $source->getContent()
        );
    }

    public function testGetContentReturnsEachMatchingRow(): void
    {
        $source = $this->source([
            [
                'scope' => 'default',
                'scope_id' => 0,
                'path' => 'design/footer/absolute_footer',
                'value' => 'footer html',
            ],
            [
                'scope' => 'stores',
                'scope_id' => 1,
                'path' => 'design/head/includes',
                'value' => 'store-specific script',
            ],
        ]);

        $content = $source->getContent();

        $this->assertCount(2, $content);
        $this->assertSame('footer html', $content['design_config:design/footer/absolute_footer:default:0']);
        $this->assertSame('store-specific script', $content['design_config:design/head/includes:stores:1']);
    }

    public function testGetContentReturnsEmptyArrayWhenConnectionThrows(): void
    {
        $resourceConnection = $this->createStub(ResourceConnection::class);
        $resourceConnection->method('getConnection')->willThrowException(new RuntimeException('boom'));

        $source = new DesignConfigContentSource($resourceConnection);

        $this->assertSame([], $source->getContent());
    }
}
