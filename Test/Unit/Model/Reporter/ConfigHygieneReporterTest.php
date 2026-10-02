<?php
declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Test\Unit\Model\Reporter;

use Magento\Framework\App\Config\ScopeConfigInterface;
use PHPUnit\Framework\TestCase;
use StackNuts\StackGauge\Api\Field\Field;
use StackNuts\StackGauge\Api\Section\Section;
use StackNuts\StackGaugeSecurity\Model\Reporter\ConfigHygieneReporter;

class ConfigHygieneReporterTest extends TestCase
{
    public function testGetStatusFlagsRiskySettings(): void
    {
        $scopeConfig = $this->createMock(ScopeConfigInterface::class);
        $scopeConfig->method('isSetFlag')->willReturnMap([
            ['dev/debug/template_hints_storefront', 'default', true],
            ['dev/debug/template_hints_admin', 'default', false],
            ['dev/css/minify_files', 'default', false],
            ['dev/js/minify_files', 'default', false],
            ['dev/static/sign', 'default', false],
        ]);

        $reporter = new ConfigHygieneReporter($scopeConfig, new Field(), new Section());
        $fields = $reporter->getStatus()['general']->getFields();

        $this->assertTrue($fields['template_hints_enabled']->getValue());
        $this->assertTrue($fields['css_minify_disabled']->getValue());
        $this->assertTrue($fields['js_minify_disabled']->getValue());
        $this->assertTrue($fields['static_content_signing_disabled']->getValue());
    }

    public function testGetStatusReportsHealthyDefaults(): void
    {
        $scopeConfig = $this->createMock(ScopeConfigInterface::class);
        $scopeConfig->method('isSetFlag')->willReturnMap([
            ['dev/debug/template_hints_storefront', 'default', false],
            ['dev/debug/template_hints_admin', 'default', false],
            ['dev/css/minify_files', 'default', true],
            ['dev/js/minify_files', 'default', true],
            ['dev/static/sign', 'default', true],
        ]);

        $reporter = new ConfigHygieneReporter($scopeConfig, new Field(), new Section());
        $fields = $reporter->getStatus()['general']->getFields();

        $this->assertFalse($fields['template_hints_enabled']->getValue());
        $this->assertFalse($fields['css_minify_disabled']->getValue());
        $this->assertFalse($fields['js_minify_disabled']->getValue());
        $this->assertFalse($fields['static_content_signing_disabled']->getValue());
    }
}
