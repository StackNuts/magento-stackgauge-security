<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Test\Unit\Model\Util;

use PHPUnit\Framework\TestCase;
use StackNuts\StackGaugeSecurity\Model\Util\SignatureSetValidator;

class SignatureSetValidatorTest extends TestCase
{
    private function signature(array $overrides = []): array
    {
        return array_merge([
            'id' => 'test-sig',
            'name' => 'Test',
            'severity' => 'critical',
            'target' => ['pub_php'],
            'pattern_type' => 'literal',
            'pattern' => 'marker',
        ], $overrides);
    }

    public function testAcceptsAWellFormedSet(): void
    {
        $validator = new SignatureSetValidator();

        $this->assertTrue($validator->isValid(['signatures' => [$this->signature()]]));
    }

    public function testRejectsMissingSignaturesKey(): void
    {
        $this->assertFalse((new SignatureSetValidator())->isValid(['version' => '1']));
    }

    public function testRejectsADuplicateId(): void
    {
        $this->assertFalse((new SignatureSetValidator())->isValid([
            'signatures' => [$this->signature(), $this->signature()],
        ]));
    }

    public function testRejectsAnUnknownSeverity(): void
    {
        $this->assertFalse((new SignatureSetValidator())->isValid([
            'signatures' => [$this->signature(['severity' => 'urgent'])],
        ]));
    }

    public function testRejectsAnEmptyTarget(): void
    {
        $this->assertFalse((new SignatureSetValidator())->isValid([
            'signatures' => [$this->signature(['target' => []])],
        ]));
    }

    public function testRejectsARegexThatDoesNotCompile(): void
    {
        $this->assertFalse((new SignatureSetValidator())->isValid([
            'signatures' => [$this->signature(['pattern_type' => 'regex', 'pattern' => '/unclosed[/'])],
        ]));
    }

    public function testAcceptsAValidRegex(): void
    {
        $this->assertTrue((new SignatureSetValidator())->isValid([
            'signatures' => [$this->signature(['pattern_type' => 'regex', 'pattern' => '/eval\s*\(/i'])],
        ]));
    }

    public function testRejectsAnEmptySet(): void
    {
        $this->assertFalse((new SignatureSetValidator())->isValid(['signatures' => []]));
    }

    public function testRejectsNonStringIdAndPatternWithoutThrowing(): void
    {
        $validator = new SignatureSetValidator();

        $this->assertFalse($validator->isValid(['signatures' => [$this->signature(['id' => ['x']])]]));
        $this->assertFalse($validator->isValid(['signatures' => [$this->signature(['pattern' => ['x']])]]));
        $this->assertFalse($validator->isValid(['signatures' => [$this->signature(['target' => [1]])]]));
        $this->assertFalse($validator->isValid(['signatures' => [$this->signature(['name' => ['x']])]]));
    }

    public function testRejectsAnOverlongPatternAndAnOversizedSet(): void
    {
        $validator = new SignatureSetValidator();

        $this->assertFalse($validator->isValid([
            'signatures' => [$this->signature(['pattern' => str_repeat('a', 2001)])],
        ]));

        $many = [];
        for ($i = 0; $i < 501; $i++) {
            $many[] = $this->signature(['id' => 'sig-' . $i]);
        }
        $this->assertFalse($validator->isValid(['signatures' => $many]));
    }

    public function testRejectsNestedQuantifiers(): void
    {
        foreach (['/(a+)+$/', '/(.*)*x/', '/(\\w+\\s*)+z/', '/(a|b*){2,}/'] as $pattern) {
            $this->assertFalse((new SignatureSetValidator())->isValid([
                'signatures' => [$this->signature(['pattern_type' => 'regex', 'pattern' => $pattern])],
            ]), $pattern);
        }
    }

    public function testAcceptsTheBundledSet(): void
    {
        $bundled = json_decode((string)file_get_contents(dirname(__DIR__, 4) . '/etc/signatures.json'), true);

        $this->assertTrue((new SignatureSetValidator())->isValid($bundled));
    }
}
