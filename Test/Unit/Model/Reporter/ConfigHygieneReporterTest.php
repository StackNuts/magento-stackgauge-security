<?php
declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Test\Unit\Model\Reporter;

use Magento\Framework\App\Config\ScopeConfigInterface;
use PHPUnit\Framework\TestCase;
use StackNuts\StackGauge\Api\Field\Field;
use StackNuts\StackGauge\Api\Section\Section;
use Magento\Store\Api\Data\StoreInterface;
use Magento\Store\Model\StoreManagerInterface;
use StackNuts\StackGaugeSecurity\Model\Reporter\ConfigHygieneReporter;

class ConfigHygieneReporterTest extends TestCase
{
    /**
     * @param list<int> $storeIds
     */
    private function storeManager(array $storeIds): StoreManagerInterface
    {
        $stores = array_map(function (int $id) {
            $store = $this->createStub(StoreInterface::class);
            $store->method('getId')->willReturn($id);

            return $store;
        }, $storeIds);
        $manager = $this->createStub(StoreManagerInterface::class);
        $manager->method('getStores')->willReturn($stores);

        return $manager;
    }

    public function testFlagsTemplateHintsEnabledOnlyInOneStoreView(): void
    {
        $scopeConfig = $this->createMock(ScopeConfigInterface::class);
        $scopeConfig->method('isSetFlag')->willReturnCallback(
            static fn (string $path, string $scope, $code = null): bool => match (true) {
                $path === 'dev/debug/template_hints_storefront' && $scope === 'store' => $code === 2,
                $path === 'dev/static/sign' => true,
                default => false,
            }
        );

        $reporter = new ConfigHygieneReporter($scopeConfig, $this->storeManager([1, 2]), new Field(), new Section());
        $fields = $reporter->getStatus()['general']->getFields();

        $this->assertTrue($fields['template_hints_enabled']->getValue());
    }

    public function testGetStatusFlagsRiskySettings(): void
    {
        $scopeConfig = $this->createMock(ScopeConfigInterface::class);
        $scopeConfig->method('isSetFlag')->willReturnMap([
            ['dev/debug/template_hints_storefront', 'default', true],
            ['dev/debug/template_hints_admin', 'default', false],
            ['dev/static/sign', 'default', false],
        ]);

        $reporter = new ConfigHygieneReporter($scopeConfig, $this->storeManager([]), new Field(), new Section());
        $fields = $reporter->getStatus()['general']->getFields();

        $this->assertTrue($fields['template_hints_enabled']->getValue());
        $this->assertTrue($fields['static_content_signing_disabled']->getValue());
    }

    public function testGetStatusReportsHealthyDefaults(): void
    {
        $scopeConfig = $this->createMock(ScopeConfigInterface::class);
        $scopeConfig->method('isSetFlag')->willReturnMap([
            ['dev/debug/template_hints_storefront', 'default', false],
            ['dev/debug/template_hints_admin', 'default', false],
            ['dev/static/sign', 'default', true],
        ]);

        $reporter = new ConfigHygieneReporter($scopeConfig, $this->storeManager([]), new Field(), new Section());
        $fields = $reporter->getStatus()['general']->getFields();

        $this->assertFalse($fields['template_hints_enabled']->getValue());
        $this->assertFalse($fields['static_content_signing_disabled']->getValue());
    }
}
