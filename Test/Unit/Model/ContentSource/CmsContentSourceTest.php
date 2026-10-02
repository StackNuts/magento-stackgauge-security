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
use StackNuts\StackGaugeSecurity\Model\ContentSource\CmsContentSource;

class CmsContentSourceTest extends TestCase
{
    /**
     * @param list<list<array<string, mixed>>> $fetchAllResults Successive fetchAll() return
     *     values, one per expected batch query, e.g. [[row1, row2], []] for one batch then end.
     */
    private function source(array $fetchAllResults): CmsContentSource
    {
        $select = $this->createMock(Select::class);
        $select->method('from')->willReturn($select);
        $select->method('where')->willReturn($select);
        $select->method('order')->willReturn($select);
        $select->method('limit')->willReturn($select);

        $connection = $this->createMock(AdapterInterface::class);
        $connection->method('select')->willReturn($select);
        $connection->method('fetchAll')->willReturn(...array_map(
            static fn (array $rows) => $rows,
            $fetchAllResults
        ));

        $resourceConnection = $this->createStub(ResourceConnection::class);
        $resourceConnection->method('getConnection')->willReturn($connection);
        $resourceConnection->method('getTableName')->willReturnArgument(0);

        return new CmsContentSource($resourceConnection);
    }

    private function consume(\Generator $generator): array
    {
        $batches = [];
        foreach ($generator as $batch) {
            $batches[] = $batch;
        }

        return [$batches, $generator->getReturn()];
    }

    public function testYieldsOneBatchWhenUnderTheBatchSize(): void
    {
        $source = $this->source([
            [['block_id' => 1, 'identifier' => 'footer', 'content' => '<p>Footer</p>']],
            [],
        ]);

        [$batches, $return] = $this->consume($source->getBlockContentBatches());

        $this->assertSame([['cms_block:footer' => '<p>Footer</p>']], $batches);
        $this->assertFalse($return['truncated']);
    }

    public function testPagesThroughMultipleBatches(): void
    {
        // A batch returning exactly BATCH_SIZE rows signals "there may be more" - keyset
        // pagination only stops on a short (or empty) batch, so the first batch here must be
        // a full 500 rows to force a second query.
        $firstBatch = [];
        for ($id = 1; $id <= 500; $id++) {
            $firstBatch[] = ['block_id' => $id, 'identifier' => "block-{$id}", 'content' => 'x'];
        }

        $source = $this->source([
            $firstBatch,
            [['block_id' => 501, 'identifier' => 'b', 'content' => 'two']],
            [],
        ]);

        [$batches, $return] = $this->consume($source->getBlockContentBatches());

        $this->assertCount(2, $batches);
        $this->assertCount(500, $batches[0]);
        $this->assertSame(['cms_block:b' => 'two'], $batches[1]);
        $this->assertFalse($return['truncated']);
    }

    public function testPageContentIsKeyedByPagePrefix(): void
    {
        $source = $this->source([
            [['page_id' => 1, 'identifier' => 'home', 'content' => '<p>Home</p>']],
            [],
        ]);

        [$batches] = $this->consume($source->getPageContentBatches());

        $this->assertSame([['cms_page:home' => '<p>Home</p>']], $batches);
    }

    public function testFlagsTruncatedWhenTheSafetyBackstopIsHit(): void
    {
        // 40 full batches of 500 = 20,000 rows, exactly MAX_TOTAL_ROWS - should stop and flag
        // truncated without needing a 41st (end-of-data) query.
        $id = 0;
        $fullBatches = array_fill(0, 40, null);
        $fetchAllResults = array_map(static function () use (&$id): array {
            $rows = [];
            for ($i = 0; $i < 500; $i++) {
                $id++;
                $rows[] = ['block_id' => $id, 'identifier' => "block-{$id}", 'content' => 'x'];
            }

            return $rows;
        }, $fullBatches);

        $source = $this->source($fetchAllResults);

        [$batches, $return] = $this->consume($source->getBlockContentBatches());

        $this->assertCount(40, $batches);
        $this->assertTrue($return['truncated']);
    }

    public function testReturnsEmptyGeneratorWhenConnectionThrows(): void
    {
        $resourceConnection = $this->createStub(ResourceConnection::class);
        $resourceConnection->method('getConnection')->willThrowException(new RuntimeException('boom'));

        $source = new CmsContentSource($resourceConnection);

        [$batches, $return] = $this->consume($source->getBlockContentBatches());

        $this->assertSame([], $batches);
        $this->assertFalse($return['truncated']);
    }
}
