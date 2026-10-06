<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Test\Unit\Model\Reporter;

use Generator;
use PHPUnit\Framework\TestCase;
use StackNuts\StackGauge\Api\Field\Field;
use StackNuts\StackGauge\Api\Section\Section;
use StackNuts\StackGaugeSecurity\Model\ContentSource\CmsContentSource;
use StackNuts\StackGaugeSecurity\Model\ContentSource\DesignConfigContentSource;
use StackNuts\StackGaugeSecurity\Model\Reporter\ContentSignatureReporter;
use StackNuts\StackGaugeSecurity\Model\Util\ContentSignatureScanner;
use StackNuts\StackGaugeSecurity\Model\Util\GeneratedCodeScanner;
use StackNuts\StackGaugeSecurity\Model\Util\PubExecutableScanner;
use StackNuts\StackGaugeSecurity\Model\Util\PubFileContentReader;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureStore;

class ContentSignatureReporterTest extends TestCase
{
    /**
     * @param list<array<string, string>> $batches
     */
    private function batchGenerator(array $batches, bool $truncated = false): Generator
    {
        foreach ($batches as $batch) {
            yield $batch;
        }

        return ['truncated' => $truncated];
    }

    /**
     * @param list<array> $matches
     */
    private function reporter(
        array $matches = [],
        string $version = '2026.10.0',
        int $signatureCount = 7,
        bool $cmsTruncated = false
    ): ContentSignatureReporter {
        $signatureStore = $this->createStub(SignatureStore::class);
        $signatureStore->method('getVersion')->willReturn($version);
        $signatureStore->method('getSignatures')->willReturn(array_fill(0, $signatureCount, []));

        $scanner = $this->createStub(ContentSignatureScanner::class);
        $scanner->method('scan')->willReturnCallback(
            static fn (array $signatures, string $target, array $content): array => $target === 'cms_content'
                ? $matches
                : []
        );

        $cmsContentSource = $this->createStub(CmsContentSource::class);
        $cmsContentSource->method('getBlockContentBatches')->willReturnCallback(
            fn (): Generator => $this->batchGenerator([['cms_block:placeholder' => 'x']], $cmsTruncated)
        );
        $cmsContentSource->method('getPageContentBatches')->willReturnCallback(
            fn (): Generator => $this->batchGenerator([])
        );

        $designConfigContentSource = $this->createStub(DesignConfigContentSource::class);
        $designConfigContentSource->method('getContent')->willReturn([]);

        $pubExecutableScanner = $this->createStub(PubExecutableScanner::class);
        $pubExecutableScanner->method('scan')->willReturn([]);

        $pubFileContentReader = $this->createStub(PubFileContentReader::class);
        $pubFileContentReader->method('readContents')->willReturn([]);

        $generatedCodeScanner = $this->createStub(GeneratedCodeScanner::class);
        $generatedCodeScanner->method('scan')->willReturn(['matches' => [], 'truncated' => false]);

        return new ContentSignatureReporter(
            $signatureStore,
            $scanner,
            $cmsContentSource,
            $designConfigContentSource,
            $pubExecutableScanner,
            $pubFileContentReader,
            $generatedCodeScanner,
            new Field(),
            new Section()
        );
    }

    public function testGetStatusReportsTheSignatureSetVersionAndCount(): void
    {
        $status = $this->reporter(version: '2026.10.0', signatureCount: 7)->getStatus();
        $fields = $status['general']->getFields();

        $this->assertSame('2026.10.0', $fields['signature_set_version']->getValue());
        $this->assertSame(7, $fields['signature_count']->getValue());
    }

    public function testGetStatusReportsNoMatchesWhenCleanOfContent(): void
    {
        $status = $this->reporter([])->getStatus();
        $fields = $status['general']->getFields();

        $this->assertFalse($fields['matches_detected']->getValue());
        $this->assertSame(0, $fields['critical_matches_detected']->getValue());
        $this->assertFalse($fields['content_scan_truncated']->getValue());
        $this->assertSame([], $status['content_signature_matches']->getRows());
    }

    public function testGetStatusReportsMatchesAndCriticalCount(): void
    {
        $matches = [
            [
                'location' => 'cms_block:footer',
                'signature_id' => 'sig-1',
                'name' => 'Sig One',
                'severity' => 'critical',
            ],
            [
                'location' => 'design_config:head_includes',
                'signature_id' => 'sig-2',
                'name' => 'Sig Two',
                'severity' => 'warning',
            ],
        ];

        $status = $this->reporter($matches)->getStatus();
        $fields = $status['general']->getFields();

        $this->assertTrue($fields['matches_detected']->getValue());
        $this->assertSame(1, $fields['critical_matches_detected']->getValue());
        $this->assertCount(2, $status['content_signature_matches']->getRows());
    }

    public function testMatchRowsIncludeBothTheSignatureIdAndItsName(): void
    {
        $matches = [
            [
                'location' => 'cms_block:footer',
                'signature_id' => 'magecart-atob-eval',
                'name' => 'eval(atob(',
                'severity' => 'critical',
            ],
        ];

        $status = $this->reporter($matches)->getStatus();
        $row = $status['content_signature_matches']->getRows()[0]->getValue();

        $this->assertSame('magecart-atob-eval', $row['signature_id']->getValue());
        $this->assertSame('eval(atob(', $row['signature_name']->getValue());
    }

    public function testGetStatusReportsCmsScanTruncated(): void
    {
        $status = $this->reporter(cmsTruncated: true)->getStatus();
        $fields = $status['general']->getFields();

        $this->assertTrue($fields['content_scan_truncated']->getValue());
    }
}
