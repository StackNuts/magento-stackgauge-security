<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Controller\Adminhtml\System\Config;

use Magento\Backend\App\Action;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureFeedFetcher;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureStatusText;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureStore;
use Throwable;

/**
 * Runs SignatureFeedFetcher::refresh() immediately from Stores > Configuration, for
 * testing/verifying a fresh signature pull without waiting for the daily FetchSignatureFeed
 * cron - see that cron class's own docblock. Reuses the stock config ACL
 * (Magento_Config::config), same precedent as the core StackGauge module's TestPing controller,
 * rather than declaring a module-specific resource just for this.
 */
class FetchSignatures extends Action implements HttpPostActionInterface
{
    public const ADMIN_RESOURCE = 'Magento_Config::config';

    /**
     * @param Action\Context $context
     * @param JsonFactory $resultJsonFactory
     * @param SignatureFeedFetcher $fetcher
     * @param SignatureStore $signatureStore
     * @param SignatureStatusText $statusText
     */
    public function __construct(
        Action\Context $context,
        private readonly JsonFactory $resultJsonFactory,
        private readonly SignatureFeedFetcher $fetcher,
        private readonly SignatureStore $signatureStore,
        private readonly SignatureStatusText $statusText
    ) {
        parent::__construct($context);
    }

    /**
     * Refreshes the feed, then reports the resulting active set (version/count/source) the same
     * way whether the fetch itself succeeded or not - a failed fetch still has an active set
     * (the previous cache, or the bundled fallback), which is exactly what's useful to confirm.
     */
    public function execute(): Json
    {
        $result = $this->resultJsonFactory->create();

        try {
            $success = $this->fetcher->refresh();
        } catch (Throwable $e) {
            return $result->setData([
                'success' => false,
                'message' => (string)__('Signature feed refresh threw an error: %1', $e->getMessage()),
            ]);
        }

        $status = $this->statusText->build(
            $this->signatureStore->getVersion(),
            count($this->signatureStore->getSignatures()),
            $this->signatureStore->getSource()
        );

        if (!$success) {
            $lastFetch = $this->signatureStore->getLastFeedFetch();

            return $result->setData([
                'success' => false,
                'message' => (string)__(
                    'Fetch failed: %1. %2',
                    $lastFetch['message'] ?? __('unknown error'),
                    $status
                ),
            ]);
        }

        return $result->setData([
            'success' => true,
            'message' => (string)__('Fetched successfully. %1', $status),
        ]);
    }
}
