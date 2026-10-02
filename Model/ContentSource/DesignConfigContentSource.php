<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\ContentSource;

use Magento\Framework\App\ResourceConnection;
use Throwable;

/**
 * Admin-editable HTML/JS config values - raw markup an admin can paste in with no review step,
 * rendered unescaped on every storefront page, and in practice a Magecart injection point just
 * as common as a compromised CMS block.
 *
 * Queries core_config_data directly via ResourceConnection rather than ScopeConfigInterface,
 * for the same reason CmsContentSource bypasses the CMS repository layer: ScopeConfigInterface
 * can only look up one known path at a time, but KNOWN_INJECTABLE_PATHS isn't the only place
 * this matters - a signature could be smuggled into any config value an admin can edit, not
 * just the handful of paths with "script" in the name. So alongside the known list, every row
 * whose value contains a <script tag or an http-equiv meta-refresh/CSP override is pulled too,
 * across every scope and store, in one query.
 */
class DesignConfigContentSource
{
    /**
     * Config paths that are HTML/JS by design - the highest-confidence Magecart injection
     * points, checked regardless of what their value looks like.
     *
     * @var list<string>
     */
    private const KNOWN_INJECTABLE_PATHS = [
        'design/head/includes',
        'design/head/demonotice',
        'design/footer/absolute_footer',
        'design/footer/copyright',
        'design/header/welcome',
    ];

    /**
     * @param ResourceConnection $resourceConnection
     */
    public function __construct(private readonly ResourceConnection $resourceConnection)
    {
    }

    /**
     * Every matching core_config_data value, keyed by "design_config:<path>:<scope>:<scope_id>".
     *
     * @return array<string, string>
     */
    public function getContent(): array
    {
        try {
            $connection = $this->resourceConnection->getConnection();
            $table = $this->resourceConnection->getTableName('core_config_data');

            $select = $connection->select()
                ->from($table, ['scope', 'scope_id', 'path', 'value'])
                ->where('value IS NOT NULL')
                ->where("value != ''")
                ->where(
                    $connection->quoteInto('path IN (?)', self::KNOWN_INJECTABLE_PATHS)
                    . " OR value LIKE '%<script%' OR value LIKE '%http-equiv%'"
                );

            $content = [];
            foreach ($connection->fetchAll($select) as $row) {
                $location = sprintf(
                    'design_config:%s:%s:%s',
                    $row['path'],
                    $row['scope'],
                    $row['scope_id']
                );
                $content[$location] = (string)$row['value'];
            }

            return $content;
        } catch (Throwable) {
            // Best-effort - a DB failure must not fail this reporter or the whole report.
            return [];
        }
    }
}
