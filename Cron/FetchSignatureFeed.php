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
 * Daily refresh of the cached signature feed. Runs in its own cron group (configured with
 * use_separate_process=1, see etc/cron_groups.xml) rather than StackGauge's "stackgauge" group, so
 * a slow or unreachable GitHub download runs in its own PHP process and can never delay report
 * generation or other cron groups. Sleeps a random 0-$maxJitterSeconds first so a fleet of stores
 * doesn't hit GitHub at the same second. Respects the "Signature Feed" admin toggle, and never throws - a failed refresh
 * simply leaves the previous cached set in place (see SignatureFeedFetcher::refresh()).
 */
class FetchSignatureFeed
{
    private const XML_PATH_FEED_ENABLED = 'stacknuts_stackgauge/general/signature_feed_enabled';

    /**
     * @param SignatureFeedFetcher $fetcher
     * @param ScopeConfigInterface $scopeConfig
     * @param LoggerInterface $logger
     * @param int $maxJitterSeconds Upper bound of the random start delay; 0 disables it.
     */
    public function __construct(
        private readonly SignatureFeedFetcher $fetcher,
        private readonly ScopeConfigInterface $scopeConfig,
        private readonly LoggerInterface $logger,
        private readonly int $maxJitterSeconds = 600
    ) {
    }

    public function execute(): void
    {
        try {
            if (!$this->scopeConfig->isSetFlag(self::XML_PATH_FEED_ENABLED, ScopeInterface::SCOPE_STORE)) {
                return;
            }

            if ($this->maxJitterSeconds > 0) {
                // phpcs:ignore Magento2.Functions.DiscouragedFunction.Discouraged
                sleep(random_int(0, $this->maxJitterSeconds));
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
