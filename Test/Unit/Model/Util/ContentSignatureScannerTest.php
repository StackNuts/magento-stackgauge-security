<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Test\Unit\Model\Util;

use PHPUnit\Framework\TestCase;
use StackNuts\StackGaugeSecurity\Model\Util\ContentSignatureScanner;

class ContentSignatureScannerTest extends TestCase
{
    private function signature(array $overrides = []): array
    {
        return array_merge([
            'id' => 'test-sig',
            'name' => 'Test Signature',
            'severity' => 'critical',
            'target' => ['cms_content'],
            'pattern_type' => 'literal',
            'pattern' => 'eval(base64_decode(',
        ], $overrides);
    }

    public function testMatchesLiteralPatternAgainstMatchingContent(): void
    {
        $scanner = new ContentSignatureScanner();

        $matches = $scanner->scan(
            [$this->signature()],
            'cms_content',
            ['cms_block:footer' => '<?php eval(base64_decode($x)); ?>']
        );

        $this->assertCount(1, $matches);
        $this->assertSame('cms_block:footer', $matches[0]['location']);
        $this->assertSame('test-sig', $matches[0]['signature_id']);
        $this->assertSame('critical', $matches[0]['severity']);
    }

    public function testNoMatchWhenContentDoesNotContainThePattern(): void
    {
        $scanner = new ContentSignatureScanner();

        $matches = $scanner->scan([$this->signature()], 'cms_content', ['cms_block:footer' => 'hello world']);

        $this->assertSame([], $matches);
    }

    public function testSignatureOnlyRunsAgainstItsDeclaredTarget(): void
    {
        $scanner = new ContentSignatureScanner();
        $signature = $this->signature(['target' => ['pub_php']]);

        $matches = $scanner->scan(
            [$signature],
            'cms_content',
            ['cms_block:footer' => '<?php eval(base64_decode($x)); ?>']
        );

        $this->assertSame([], $matches);
    }

    public function testMatchesRegexPattern(): void
    {
        $scanner = new ContentSignatureScanner();
        $signature = $this->signature([
            'pattern_type' => 'regex',
            'pattern' => '/assert\s*\(\s*\$_(POST|REQUEST|GET)/',
        ]);

        $matches = $scanner->scan([$signature], 'cms_content', ['pub_file:shell.php' => 'assert($_POST[1]);']);

        $this->assertCount(1, $matches);
    }

    public function testOneContentEntryCanMatchMultipleSignatures(): void
    {
        $scanner = new ContentSignatureScanner();
        $signatures = [
            $this->signature(['id' => 'sig-a', 'pattern' => 'eval(']),
            $this->signature(['id' => 'sig-b', 'pattern' => 'base64_decode(']),
        ];

        $matches = $scanner->scan($signatures, 'cms_content', ['cms_block:footer' => 'eval(base64_decode($x))']);

        $this->assertCount(2, $matches);
    }

    public function testUnknownPatternTypeNeverMatches(): void
    {
        $scanner = new ContentSignatureScanner();
        $signature = $this->signature(['pattern_type' => 'unsupported']);

        $matches = $scanner->scan([$signature], 'cms_content', ['cms_block:footer' => 'eval(base64_decode($x))']);

        $this->assertSame([], $matches);
    }

    /**
     * A regex that errors (here: PCRE's backtrack limit) must not quietly read as "no match".
     */
    public function testARegexThatFailsToRunIsReportedRatherThanSilentlyNotMatching(): void
    {
        $previousJit = ini_get('pcre.jit');
        $previousLimit = ini_get('pcre.backtrack_limit');
        ini_set('pcre.jit', '0');
        ini_set('pcre.backtrack_limit', '100');

        try {
            $scanner = new ContentSignatureScanner();
            $matches = $scanner->scan([[
                'id' => 'catastrophic',
                'name' => 'Catastrophic',
                'severity' => 'critical',
                'target' => ['cms_content'],
                'pattern_type' => 'regex',
                'pattern' => '/(a+)+$/',
            ]], 'cms_content', ['block' => str_repeat('a', 30) . 'b']);
        } finally {
            ini_set('pcre.jit', (string)$previousJit);
            ini_set('pcre.backtrack_limit', (string)$previousLimit);
        }

        $this->assertSame([], $matches);
        $this->assertSame(['catastrophic'], $scanner->getErroredSignatureIds());
    }

    public function testLiteralPatternsAreCaseInsensitive(): void
    {
        $matches = (new ContentSignatureScanner())->scan(
            [$this->signature()],
            'cms_content',
            ['a' => 'EVAL(BASE64_DECODE($x))']
        );

        $this->assertCount(1, $matches);
    }

    public function testBundledSignaturesIgnoreCaseWhitespaceAndAtPrefix(): void
    {
        $bundled = json_decode((string)file_get_contents(dirname(__DIR__, 4) . '/etc/signatures.json'), true);
        $bodies = [
            'EVAL(base64_decode($x));',
            '@eval( base64_decode ($x));',
            "eval\n(\tgzinflate(\$x));",
            'ASSERT ( $_POST["x"] );',
            'System( $_GET["c"] );',
        ];

        foreach ($bodies as $body) {
            $this->assertNotSame(
                [],
                (new ContentSignatureScanner())->scan($bundled['signatures'], 'pub_php', ['f.php' => $body]),
                $body
            );
        }

        $this->assertNotSame([], (new ContentSignatureScanner())->scan(
            $bundled['signatures'],
            'cms_content',
            ['b' => '<script>EVAL ( atob("x"))</script>']
        ));
    }

    public function testStopsScanningOnceTheTimeBudgetIsSpent(): void
    {
        $scanner = new ContentSignatureScanner();
        $scanner->resetBudget();
        $property = new \ReflectionProperty($scanner, 'budgetStartedAt');
        $property->setValue($scanner, microtime(true) - 10000);

        $matches = $scanner->scan([$this->signature()], 'cms_content', ['a' => 'eval(base64_decode(']);

        $this->assertSame([], $matches);
        $this->assertTrue($scanner->wasBudgetExceeded());

        $scanner->resetBudget();
        $this->assertFalse($scanner->wasBudgetExceeded());
    }
}
