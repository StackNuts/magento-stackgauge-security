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
}
