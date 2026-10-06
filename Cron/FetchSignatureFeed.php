<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Cron;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Store\Model\ScopeInterface;
use Psr\Log\LoggerInterface;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureFeedFetcher;
use Throwable;

/**
 * Daily refresh of the cached signature feed. Runs in its own cron group rather than StackGauge's
 * "stackgauge" group, so a slow or unreachable GitHub download can never delay report
 * generation. Respects the "Signature Feed" admin toggle, and never throws - a failed refresh
 * simply leaves the previous cached set in place (see SignatureFeedFetcher::refresh()).
 */
class FetchSignatureFeed
{
    private const XML_PATH_FEED_ENABLED = 'stacknuts_stackgauge/general/signature_feed_enabled';

    /**
     * @param SignatureFeedFetcher $fetcher
     * @param ScopeConfigInterface $scopeConfig
     * @param LoggerInterface $logger
     */
    public function __construct(
        private readonly SignatureFeedFetcher $fetcher,
        private readonly ScopeConfigInterface $scopeConfig,
        private readonly LoggerInterface $logger
    ) {
    }

    public function execute(): void
    {
        try {
            if (!$this->scopeConfig->isSetFlag(self::XML_PATH_FEED_ENABLED, ScopeInterface::SCOPE_STORE)) {
                return;
            }

            $this->fetcher->refresh();
        } catch (Throwable $e) {
            $this->logger->critical(
                'StackGaugeSecurity: FetchSignatureFeed cron job failed: ' . $e->getMessage(),
                ['exception' => $e]
            );
        }
    }
}
