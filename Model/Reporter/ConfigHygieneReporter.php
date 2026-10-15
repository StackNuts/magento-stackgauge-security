<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Reporter;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\App\ScopeInterface as AppScopeInterface;
use StackNuts\StackGauge\Api\DeclaresCadenceInterface;
use StackNuts\StackGauge\Api\DeclaresSectionInterface;
use StackNuts\StackGauge\Api\DeclaresSlotInterface;
use StackNuts\StackGauge\Api\Field\Field;
use StackNuts\StackGauge\Api\MetricCatalogInterface;
use StackNuts\StackGauge\Api\MetricDefinition;
use StackNuts\StackGauge\Api\ReporterInterface;
use StackNuts\StackGauge\Api\Section\Section;
use StackNuts\StackGauge\Model\Reporter\Concern\DailyCadenceTrait;
use StackNuts\StackGauge\Model\Reporter\Concern\SecuritySectionTrait;

/**
 * Flags a fixed list of dev/debug settings that are fine on a local box but leak information
 * or cost performance left on in production - invisible from the storefront itself (unlike,
 * say, template hints, which a merchant would at least notice) until someone goes looking.
 *
 * Every flag here is read at the default scope only - these are the kind of settings that
 * get set once, globally, by whoever built the site, not something that varies per-store-view
 * in practice; a per-store override would still show up if it changed the effective default.
 */
class ConfigHygieneReporter implements ReporterInterface, DeclaresCadenceInterface, DeclaresSectionInterface, DeclaresSlotInterface, MetricCatalogInterface
{
    use DailyCadenceTrait;
    use SecuritySectionTrait;

    private const SCHEMA_VERSION = '1.0';

    /**
     * Yes/no findings the dashboard alerts on while true - see getTrackableMetrics().
     */
    private const FINDING_STATIC_SIGNING_OFF = 'config_hygiene.static_content_signing_disabled';

    private const XML_PATH_TEMPLATE_HINTS = 'dev/debug/template_hints_storefront';
    private const XML_PATH_TEMPLATE_HINTS_ADMIN = 'dev/debug/template_hints_admin';
    private const XML_PATH_STATIC_SIGN = 'dev/static/sign';

    /**
     * @param ScopeConfigInterface $scopeConfig
     * @param Field $field
     * @param Section $section
     */
    public function __construct(
        private readonly ScopeConfigInterface $scopeConfig,
        private readonly Field $field,
        private readonly Section $section
    ) {
    }

    /**
     * Payload key for the config-hygiene reporter.
     */
    public function getName(): string
    {
        return 'config_hygiene';
    }

    /**
     * Human-readable label for the config-hygiene reporter block.
     */
    public function getLabel(): string
    {
        return 'Config Hygiene';
    }

    /**
     * One-line summary of what the config-hygiene reporter covers, shown on the dashboard alongside the label.
     */
    public function getDescription(): string
    {
        return 'Dev/debug settings (template hints, static signing) that are risky or costly '
            . 'left on in production.';
    }

    /**
     * Schema version for this reporter's payload shape.
     */
    public function getSchemaVersion(): string
    {
        return self::SCHEMA_VERSION;
    }

    /**
     * Reports whether template hints and static-content signing are left in a risky state.
     */
    public function getStatus(): array
    {
        $templateHintsOn = $this->isSetFlag(self::XML_PATH_TEMPLATE_HINTS)
            || $this->isSetFlag(self::XML_PATH_TEMPLATE_HINTS_ADMIN);
        $staticSignOff = !$this->isSetFlag(self::XML_PATH_STATIC_SIGN);

        return ['general' => $this->section->facts('general', 'General', $this->getDescription(), [
            // Template hints inject the template file path into every rendered block - a
            // minor info-disclosure risk, and also visibly ugly if a merchant just forgot
            // to turn it off after debugging.
            'template_hints_enabled' => $this->field->bool(
                'Template Hints Enabled',
                $templateHintsOn,
                criticalWhen: true
            ),
            'static_content_signing_disabled' => $this->field->bool(
                'Static Content Signing Disabled',
                $staticSignOff,
                criticalWhen: true,
                metricKey: self::FINDING_STATIC_SIGNING_OFF
            ),
        ])];
    }

    /**
     * Reads a flag at the default scope - see this class's own docblock for why.
     *
     * @param string $path
     */
    private function isSetFlag(string $path): bool
    {
        return $this->scopeConfig->isSetFlag($path, AppScopeInterface::SCOPE_DEFAULT);
    }

    /**
     * Run 0 within this reporter's cadence tier.
     */
    public function getSlot(): int
    {
        return 0;
    }

    /**
     * This reporter's alertable findings - each the bool field of the same metric key.
     *
     * @return MetricDefinition[]
     */
    public function getTrackableMetrics(): array
    {
        return [
            MetricDefinition::finding(
                self::FINDING_STATIC_SIGNING_OFF,
                'Config Hygiene: Static Content Signing Disabled',
                MetricDefinition::SEVERITY_WARNING,
                'Static asset signing is turned off.',
                'Static assets can be served or cached without a way to detect tampering.'
            ),
        ];
    }
}
