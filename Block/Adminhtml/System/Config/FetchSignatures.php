<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Block\Adminhtml\System\Config;

use Magento\Backend\Block\Template\Context;
use Magento\Config\Block\System\Config\Form\Field;
use Magento\Framework\Data\Form\Element\AbstractElement;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureStatusText;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureStore;

/**
 * Renders the "Fetch Latest Signatures Now" button, same structural pattern as the core
 * StackGauge module's TestPing block - clicking it calls SignatureFeedFetcher::refresh()
 * immediately instead of waiting for the daily FetchSignatureFeed cron. The button's own result
 * line doubles as the "what version are we using" display: it shows the active set's
 * version/count/source as of page load, and updates in place to the freshly fetched set once
 * clicked - see SignatureStatusText.
 */
class FetchSignatures extends Field
{
    /**
     * @param Context $context
     * @param SignatureStore $signatureStore
     * @param SignatureStatusText $statusText
     * @param array $data
     */
    public function __construct(
        Context $context,
        private readonly SignatureStore $signatureStore,
        private readonly SignatureStatusText $statusText,
        array $data = []
    ) {
        parent::__construct($context, $data);
    }

    /**
     * Assigns the phtml template that renders the button.
     */
    protected function _prepareLayout()
    {
        parent::_prepareLayout();
        $this->setTemplate('StackNuts_StackGaugeSecurity::system/config/fetch_signatures.phtml');

        return $this;
    }

    /**
     * Strips the scope/website/default-value UI affordances before rendering.
     *
     * This is a button, not a real config value, so those don't apply.
     *
     * @param AbstractElement $element
     */
    public function render(AbstractElement $element)
    {
        $element = clone $element;
        if (method_exists($element, 'unsScope')) {
            $element->unsScope();
        }
        if (method_exists($element, 'unsCanUseWebsiteValue')) {
            $element->unsCanUseWebsiteValue();
        }
        if (method_exists($element, 'unsCanUseDefaultValue')) {
            $element->unsCanUseDefaultValue();
        }

        return parent::render($element);
    }

    /**
     * Passes the element's HTML id, the AJAX URL, and the active set's current status text to
     * the template.
     *
     * @param AbstractElement $element
     */
    protected function _getElementHtml(AbstractElement $element)
    {
        $this->addData([
            'html_id' => $element->getHtmlId(),
            'ajax_url' => $this->_urlBuilder->getUrl('stacknuts_stackgaugesecurity/system_config/fetchsignatures'),
            'status_text' => $this->statusText->build(
                $this->signatureStore->getVersion(),
                count($this->signatureStore->getSignatures()),
                $this->signatureStore->getSource()
            ),
        ]);

        return $this->_toHtml();
    }
}
