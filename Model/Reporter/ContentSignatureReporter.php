<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Reporter;

use StackNuts\StackGauge\Api\DeclaresCadenceInterface;
use StackNuts\StackGauge\Api\DeclaresSectionInterface;
use StackNuts\StackGauge\Api\Field\ArrayField;
use StackNuts\StackGauge\Api\Field\Field;
use StackNuts\StackGauge\Api\ReporterInterface;
use StackNuts\StackGauge\Api\Section\Section;
use StackNuts\StackGauge\Model\Reporter\Concern\DailyCadenceTrait;
use StackNuts\StackGauge\Model\Reporter\Concern\PlatformSectionTrait;
use StackNuts\StackGaugeSecurity\Model\ContentSource\CmsContentSource;
use StackNuts\StackGaugeSecurity\Model\ContentSource\DesignConfigContentSource;
use StackNuts\StackGaugeSecurity\Model\Util\ContentSignatureScanner;
use StackNuts\StackGaugeSecurity\Model\Util\GeneratedCodeScanner;
use StackNuts\StackGaugeSecurity\Model\Util\PubExecutableScanner;
use StackNuts\StackGaugeSecurity\Model\Util\PubFileContentReader;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureStore;

/**
 * Checks CMS block/page content, the "Miscellaneous Scripts" design config value, and files
 * PubExecutableScanner already flagged against a hand-curated set of known-bad content
 * signatures (see SignatureStore) - the webshell/Magecart-skimmer detection layer that
 * mtime-drift and filesystem-exposure checks (see SecurityReporter) can't provide, since those
 * only notice *that* something changed or is reachable, not whether its content is actually
 * malicious.
 *
 * Never reports the matched content itself, only where a match was found and which signature
 * matched it - the report pipeline is not somewhere a confirmed-malicious payload should ever
 * travel, even to StackNuts' own dashboard.
 */
class ContentSignatureReporter implements ReporterInterface, DeclaresCadenceInterface, DeclaresSectionInterface
{
    use DailyCadenceTrait;
    use PlatformSectionTrait;

    private const SCHEMA_VERSION = '1.0';

    /**
     * @param SignatureStore $signatureStore
     * @param ContentSignatureScanner $scanner
     * @param CmsContentSource $cmsContentSource
     * @param DesignConfigContentSource $designConfigContentSource
     * @param PubExecutableScanner $pubExecutableScanner
     * @param PubFileContentReader $pubFileContentReader
     * @param GeneratedCodeScanner $generatedCodeScanner
     * @param Field $field
     * @param Section $section
     */
    public function __construct(
        private readonly SignatureStore $signatureStore,
        private readonly ContentSignatureScanner $scanner,
        private readonly CmsContentSource $cmsContentSource,
        private readonly DesignConfigContentSource $designConfigContentSource,
        private readonly PubExecutableScanner $pubExecutableScanner,
        private readonly PubFileContentReader $pubFileContentReader,
        private readonly GeneratedCodeScanner $generatedCodeScanner,
        private readonly Field $field,
        private readonly Section $section
    ) {
    }

    /**
     * Payload key for the content signature reporter.
     */
    public function getName(): string
    {
        return 'content_signatures';
    }

    /**
     * Human-readable label for the content signature reporter block.
     */
    public function getLabel(): string
    {
        return 'Content Signatures';
    }

    /**
     * One-line summary of what the content signature reporter covers.
     */
    public function getDescription(): string
    {
        return 'CMS block/page content, the storefront <head> script config, and suspicious '
            . 'pub/ files checked against known webshell and Magecart-skimmer content signatures.';
    }

    /**
     * Schema version for this reporter's payload shape.
     */
    public function getSchemaVersion(): string
    {
        return self::SCHEMA_VERSION;
    }

    /**
     * Reports the signature set's own version/size plus every content match found.
     */
    public function getStatus(): array
    {
        $signatures = $this->signatureStore->getSignatures();

        [$cmsMatches, $cmsTruncated] = $this->scanCmsContent($signatures);
        $generated = $this->generatedCodeScanner->scan($signatures);
        $designConfigContent = $this->designConfigContentSource->getContent();
        $pubFileContent = $this->pubFileContentReader->readContents($this->pubExecutableScanner->scan());

        $matches = [
            ...$cmsMatches,
            ...$generated['matches'],
            ...$this->scanner->scan($signatures, 'design_config', $designConfigContent),
            ...$this->scanner->scan($signatures, 'pub_php', $pubFileContent),
        ];
        $criticalMatches = array_values(array_filter(
            $matches,
            static fn (array $match): bool => $match['severity'] === Field::SEVERITY_CRITICAL
        ));

        return [
            'general' => $this->section->facts('general', 'General', '', [
                'signature_set_version' => $this->field->varchar(
                    'Signature Set Version',
                    $this->signatureStore->getVersion() ?? 'unknown'
                ),
                'signature_count' => $this->field->number('Signatures Loaded', count($signatures)),
                'matches_detected' => $this->field->bool(
                    'Content Signature Matches Detected',
                    $matches !== [],
                    criticalWhen: true
                ),
                'critical_matches_detected' => $this->field->number(
                    'Critical Matches',
                    count($criticalMatches),
                    severity: $criticalMatches !== [] ? Field::SEVERITY_CRITICAL : Field::SEVERITY_OK
                ),
                // Only ever true on a CMS content library large enough to hit
                // CmsContentSource::MAX_TOTAL_ROWS - see that class's own docblock. Surfaced
                // here rather than left silent, since neither competitor project this was
                // compared against reports an equivalent "didn't scan everything" signal.
                'content_scan_truncated' => $this->field->bool('CMS Content Scan Truncated', $cmsTruncated),
                'generated_code_scan_truncated' => $this->field->bool(
                    'generated/code Scan Truncated',
                    $generated['truncated']
                ),
            ]),
            'content_signature_matches' => $this->section->table(
                'content_signature_matches',
                'Content Signature Matches',
                'Locations where known-bad content was found - see SignatureStore for the '
                    . 'signature set and ContentSignatureScanner for how matching works. Never '
                    . 'includes the matched content itself.',
                $this->matchFields($matches),
                // The same location (e.g. a CMS block) can legitimately match more than one
                // signature - skip the duplicate-row check rather than have that throw as if
                // it were a reporter bug.
                keyName: 'row_identity_not_checked'
            ),
        ];
    }

    /**
     * Scans every CMS block and page, batch by batch, against $signatures - see
     * CmsContentSource's own docblock for why this is batched (keyset-paginated, streamed)
     * rather than one flat content map.
     *
     * @param list<array> $signatures
     * @return array{0: list<array>, 1: bool} Matches, and whether either table's scan was
     *     truncated (see CmsContentSource::MAX_TOTAL_ROWS).
     */
    private function scanCmsContent(array $signatures): array
    {
        $matches = [];
        $truncated = false;

        $blockBatches = $this->cmsContentSource->getBlockContentBatches();
        foreach ($blockBatches as $batch) {
            $matches = [...$matches, ...$this->scanner->scan($signatures, 'cms_content', $batch)];
        }
        $truncated = $truncated || ($blockBatches->getReturn()['truncated'] ?? false);

        $pageBatches = $this->cmsContentSource->getPageContentBatches();
        foreach ($pageBatches as $batch) {
            $matches = [...$matches, ...$this->scanner->scan($signatures, 'cms_content', $batch)];
        }
        $truncated = $truncated || ($pageBatches->getReturn()['truncated'] ?? false);

        return [$matches, $truncated];
    }

    /**
     * Builds one row per match from ContentSignatureScanner::scan().
     *
     * @param list<array> $matches
     * @return list<ArrayField>
     */
    private function matchFields(array $matches): array
    {
        return array_map(
            fn (array $match) => $this->field->array($match['location'] . ':' . $match['signature_id'], [
                'location' => $this->field->varchar('Location', $match['location']),
                'signature_id' => $this->field->varchar('Signature ID', $match['signature_id']),
                'signature_name' => $this->field->varchar('Signature', $match['name']),
                'severity' => $this->field->varchar(
                    'Severity',
                    $match['severity'],
                    criticalValues: [Field::SEVERITY_CRITICAL]
                ),
            ]),
            $matches
        );
    }
}
