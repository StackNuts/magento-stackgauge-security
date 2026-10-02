<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\ContentSource;

use Generator;
use Magento\Framework\App\ResourceConnection;
use Throwable;

/**
 * CMS block/page content, for ContentSignatureScanner's "cms_content" target - the classic
 * Magecart injection point (a skimmer loader hidden in a block's HTML, most commonly the
 * footer/header block every page renders).
 *
 * Queries cms_block/cms_page directly via ResourceConnection rather than through
 * BlockRepositoryInterface/PageRepositoryInterface - a read-only content scan has no need for
 * the full entity hydration (event dispatch, resource model overhead) the repository layer
 * carries for every row, and on a store with a large CMS content library that overhead adds up
 * across thousands of rows for no benefit here.
 *
 * Each table is walked in BATCH_SIZE pages using keyset ("seek") pagination - WHERE id > :last
 * ORDER BY id LIMIT :size - rather than LIMIT/OFFSET: OFFSET still makes the database scan and
 * discard every skipped row server-side, so it gets slower the deeper it pages, where keyset
 * pagination stays a cheap indexed lookup regardless of depth. Each batch is yielded (and so
 * scanned and discarded by the caller) one at a time rather than collected into one giant
 * array, keeping peak memory flat regardless of table size.
 *
 * MAX_TOTAL_ROWS is a safety backstop, not the normal operating limit - real stores rarely have
 * more than a few hundred CMS blocks/pages, so this is sized well above that and is expected to
 * never trigger in practice. If it ever does, the generator's return value reports it rather
 * than silently scanning only part of the table.
 */
class CmsContentSource
{
    private const BATCH_SIZE = 500;
    private const MAX_TOTAL_ROWS = 20000;

    /**
     * @param ResourceConnection $resourceConnection
     */
    public function __construct(private readonly ResourceConnection $resourceConnection)
    {
    }

    /**
     * Yields CMS block content in batches, keyed by "cms_block:<identifier>".
     *
     * @return Generator<array<string, string>>
     */
    public function getBlockContentBatches(): Generator
    {
        return $this->contentBatches('cms_block', 'block_id', 'cms_block:');
    }

    /**
     * Yields CMS page content in batches, keyed by "cms_page:<identifier>".
     *
     * @return Generator<array<string, string>>
     */
    public function getPageContentBatches(): Generator
    {
        return $this->contentBatches('cms_page', 'page_id', 'cms_page:');
    }

    /**
     * Walks $table in keyset-paginated batches of non-empty content, yielding each batch as
     * a location => content map. Returns {truncated: bool} once exhausted (see
     * Generator::getReturn()) - true only if MAX_TOTAL_ROWS was hit before the table was.
     *
     * @param string $table Logical table name, e.g. "cms_block".
     * @param string $idColumn Primary key column, e.g. "block_id".
     * @param string $locationPrefix Prefixed onto each row's identifier for the yielded key.
     * @return Generator<array<string, string>, mixed, mixed, array{truncated: bool}>
     */
    private function contentBatches(string $table, string $idColumn, string $locationPrefix): Generator
    {
        $truncated = false;

        try {
            $connection = $this->resourceConnection->getConnection();
            $tableName = $this->resourceConnection->getTableName($table);
            $lastId = 0;
            $totalRows = 0;

            while (true) {
                $select = $connection->select()
                    ->from($tableName, [$idColumn, 'identifier', 'content'])
                    ->where('content IS NOT NULL')
                    ->where("content != ''")
                    ->where("{$idColumn} > ?", $lastId)
                    ->order("{$idColumn} ASC")
                    ->limit(self::BATCH_SIZE);

                $rows = $connection->fetchAll($select);
                if ($rows === []) {
                    break;
                }

                $batch = [];
                foreach ($rows as $row) {
                    $batch[$locationPrefix . $row['identifier']] = (string)$row['content'];
                    $lastId = (int)$row[$idColumn];
                }
                $totalRows += count($rows);

                yield $batch;

                if ($totalRows >= self::MAX_TOTAL_ROWS) {
                    $truncated = true;
                    break;
                }

                if (count($rows) < self::BATCH_SIZE) {
                    break;
                }
            }
        // phpcs:ignore Magento2.CodeAnalysis.EmptyBlock.DetectedCatch
        } catch (Throwable) {
            // Best-effort - a DB failure must not fail this reporter or the whole report;
            // whatever was yielded before the error still gets scanned.
        }

        return ['truncated' => $truncated];
    }
}
