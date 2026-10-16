<?php
declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Test\Unit\Model\Reporter;

use Magento\Framework\App\ResourceConnection;
use Magento\Framework\DB\Adapter\AdapterInterface;
use Magento\Framework\DB\Select;
use Magento\Framework\Module\ModuleListInterface;
use Magento\Framework\ObjectManagerInterface;
use Magento\TwoFactorAuth\Api\TfaInterface;
use Magento\User\Model\ResourceModel\User\Collection as AdminUserCollection;
use Magento\User\Model\ResourceModel\User\CollectionFactory as AdminUserCollectionFactory;
use PHPUnit\Framework\TestCase;
use StackNuts\StackGauge\Api\Field\Field;
use StackNuts\StackGauge\Api\Section\Section;
use StackNuts\StackGaugeSecurity\Model\Reporter\AdminAccountsReporter;
use StackNuts\StackGauge\Model\Util\Clock;

class AdminAccountsReporterTest extends TestCase
{
    private function userCollectionFactory(
        array $activeIds,
        int $locked,
        int $recentFailures,
        int $newAdmins,
        int $dormant = 0,
        int $staleLogins = 0
    ): AdminUserCollectionFactory {
        $activeIdsCollection = $this->createMock(AdminUserCollection::class);
        $activeIdsCollection->method('addFieldToFilter')->willReturnSelf();
        $activeIdsCollection->method('getAllIds')->willReturn($activeIds);

        $lockedCollection = $this->createMock(AdminUserCollection::class);
        $lockedCollection->method('addFieldToFilter')->willReturnSelf();
        $lockedCollection->method('getSize')->willReturn($locked);

        $recentFailuresCollection = $this->createMock(AdminUserCollection::class);
        $recentFailuresCollection->method('addFieldToFilter')->willReturnSelf();
        $recentFailuresCollection->method('getSize')->willReturn($recentFailures);

        $newAdminsCollection = $this->createMock(AdminUserCollection::class);
        $newAdminsCollection->method('addFieldToFilter')->willReturnSelf();
        $newAdminsCollection->method('getSize')->willReturn($newAdmins);

        $dormantCollection = $this->createMock(AdminUserCollection::class);
        $dormantCollection->method('addFieldToFilter')->willReturnSelf();
        $dormantCollection->method('getSize')->willReturn($dormant);

        $staleLoginsCollection = $this->createMock(AdminUserCollection::class);
        $staleLoginsCollection->method('addFieldToFilter')->willReturnSelf();
        $staleLoginsCollection->method('getSize')->willReturn($staleLogins);

        $factory = $this->createMock(AdminUserCollectionFactory::class);
        $factory->method('create')->willReturnOnConsecutiveCalls(
            $activeIdsCollection,
            $lockedCollection,
            $recentFailuresCollection,
            $newAdminsCollection,
            $dormantCollection,
            $staleLoginsCollection
        );

        return $factory;
    }

    private function moduleList(bool $tfaPresent, bool $bypassPresent): ModuleListInterface
    {
        $moduleList = $this->createMock(ModuleListInterface::class);
        $moduleList->method('has')->willReturnMap([
            ['Magento_TwoFactorAuth', $tfaPresent],
            ['MarkShust_DisableTwoFactorAuth', $bypassPresent],
        ]);

        return $moduleList;
    }

    /**
     * A ResourceConnection double whose getConnection() throws - fetchAdminRoleStats() catches
     * broadly and returns zeros, a safe default for tests that aren't exercising role stats.
     */
    private function resourceConnectionWithNoRoleData(): ResourceConnection
    {
        $resourceConnection = $this->createMock(ResourceConnection::class);
        $resourceConnection->method('getConnection')->willThrowException(new \RuntimeException('not configured'));

        return $resourceConnection;
    }

    /**
     * @param list<int> $fullAccessRoleIds
     * @param array{total: int, full_access: int} $roleStatsRow
     */
    private function resourceConnectionWithRoleData(array $fullAccessRoleIds, array $roleStatsRow): ResourceConnection
    {
        $select = $this->createMock(Select::class);
        $select->method('distinct')->willReturnSelf();
        $select->method('from')->willReturnSelf();
        $select->method('where')->willReturnSelf();
        $select->method('joinInner')->willReturnSelf();
        $select->method('columns')->willReturnSelf();

        $connection = $this->createMock(AdapterInterface::class);
        $connection->method('select')->willReturn($select);
        $connection->method('fetchCol')->willReturn($fullAccessRoleIds);
        $connection->method('fetchRow')->willReturn($roleStatsRow);

        $resourceConnection = $this->createMock(ResourceConnection::class);
        $resourceConnection->method('getConnection')->willReturn($connection);
        $resourceConnection->method('getTableName')->willReturnArgument(0);

        return $resourceConnection;
    }

    public function testGetStatusReportsCountsWithoutTwoFactorModule(): void
    {
        $factory = $this->userCollectionFactory([1, 2], 1, 0, 0);
        $moduleList = $this->moduleList(tfaPresent: false, bypassPresent: false);
        $objectManager = $this->createMock(ObjectManagerInterface::class);

        $reporter = new AdminAccountsReporter(
            $factory,
            $moduleList,
            $objectManager,
            $this->resourceConnectionWithNoRoleData(),
            new Clock(),
            new Field(),
            new Section()
        );

        $fields = $reporter->getStatus()['general']->getFields();

        $this->assertSame(2, $fields['total_admin_accounts']->getValue());
        $this->assertSame(1, $fields['locked_accounts']->getValue());
        $this->assertFalse($fields['two_factor_auth_enabled']->getValue());
        $this->assertFalse($fields['two_factor_auth_bypass_detected']->getValue());
        // No TFA module installed - "without 2FA" reports 0, not every active admin, since a
        // store that's never turned the feature on hasn't failed to enroll anyone.
        $this->assertSame(0, $fields['admin_accounts_without_2fa']->getValue());
    }

    /**
     * Magento\TwoFactorAuth\Api\TfaInterface::isEnabled() unconditionally returns true
     * whenever the module exists in current Magento/Mage-OS versions - it's not a usable
     * signal on its own. A known dev-convenience module (bundled with the popular Mark Shust
     * Docker Magento setup) neuters enforcement regardless of it, by plugging
     * TfaSession::isGranted() to always grant - this reporter must treat that module's mere
     * presence as "2FA is not genuinely active," not report the misleadingly-true isEnabled().
     */
    public function testBypassModulePresenceOverridesIsEnabled(): void
    {
        $factory = $this->userCollectionFactory([1], 0, 0, 0);
        $moduleList = $this->moduleList(tfaPresent: true, bypassPresent: true);

        $tfa = $this->createMock(TfaInterface::class);
        $tfa->method('isEnabled')->willReturn(true);
        $tfa->expects($this->never())->method('getProvidersToActivate');

        $objectManager = $this->createMock(ObjectManagerInterface::class);
        $objectManager->method('get')->with(TfaInterface::class)->willReturn($tfa);

        $reporter = new AdminAccountsReporter(
            $factory,
            $moduleList,
            $objectManager,
            $this->resourceConnectionWithNoRoleData(),
            new Clock(),
            new Field(),
            new Section()
        );

        $fields = $reporter->getStatus()['general']->getFields();

        $this->assertFalse($fields['two_factor_auth_enabled']->getValue());
        $this->assertTrue($fields['two_factor_auth_bypass_detected']->getValue());
        $this->assertSame(0, $fields['admin_accounts_without_2fa']->getValue());
    }

    public function testGenuinelyActiveTfaComputesTheRealEnrollmentGap(): void
    {
        $factory = $this->userCollectionFactory([1, 2], 0, 0, 0);
        $moduleList = $this->moduleList(tfaPresent: true, bypassPresent: false);

        $tfa = $this->createMock(TfaInterface::class);
        $tfa->method('isEnabled')->willReturn(true);
        $tfa->method('getProvidersToActivate')->willReturnMap([
            [1, []],
            [2, ['google']],
        ]);

        $objectManager = $this->createMock(ObjectManagerInterface::class);
        $objectManager->method('get')->with(TfaInterface::class)->willReturn($tfa);

        $reporter = new AdminAccountsReporter(
            $factory,
            $moduleList,
            $objectManager,
            $this->resourceConnectionWithNoRoleData(),
            new Clock(),
            new Field(),
            new Section()
        );

        $fields = $reporter->getStatus()['general']->getFields();

        $this->assertTrue($fields['two_factor_auth_enabled']->getValue());
        $this->assertFalse($fields['two_factor_auth_bypass_detected']->getValue());
        $this->assertSame(1, $fields['admin_accounts_without_2fa']->getValue());
    }

    public function testReportsDormantActiveAccounts(): void
    {
        $factory = $this->userCollectionFactory([1], 0, 0, 0, dormant: 3);
        $moduleList = $this->moduleList(tfaPresent: false, bypassPresent: false);
        $objectManager = $this->createMock(ObjectManagerInterface::class);

        $reporter = new AdminAccountsReporter(
            $factory,
            $moduleList,
            $objectManager,
            $this->resourceConnectionWithNoRoleData(),
            new Clock(),
            new Field(),
            new Section()
        );

        $fields = $reporter->getStatus()['general']->getFields();

        $this->assertSame(3, $fields['dormant_active_accounts']->getValue());
    }

    public function testFlagsWhenEveryActiveAdminHasFullAccess(): void
    {
        $factory = $this->userCollectionFactory([1, 2], 0, 0, 0);
        $moduleList = $this->moduleList(tfaPresent: false, bypassPresent: false);
        $objectManager = $this->createMock(ObjectManagerInterface::class);
        $resourceConnection = $this->resourceConnectionWithRoleData([1], ['total' => 2, 'full_access' => 2]);

        $reporter = new AdminAccountsReporter(
            $factory,
            $moduleList,
            $objectManager,
            $resourceConnection,
            new Clock(),
            new Field(),
            new Section()
        );

        $fields = $reporter->getStatus()['general']->getFields();

        $this->assertTrue($fields['all_active_admins_have_full_access']->getValue());
    }

    public function testDoesNotFlagWhenRolesAreSeparated(): void
    {
        $factory = $this->userCollectionFactory([1, 2], 0, 0, 0);
        $moduleList = $this->moduleList(tfaPresent: false, bypassPresent: false);
        $objectManager = $this->createMock(ObjectManagerInterface::class);
        $resourceConnection = $this->resourceConnectionWithRoleData([1], ['total' => 2, 'full_access' => 1]);

        $reporter = new AdminAccountsReporter(
            $factory,
            $moduleList,
            $objectManager,
            $resourceConnection,
            new Clock(),
            new Field(),
            new Section()
        );

        $fields = $reporter->getStatus()['general']->getFields();

        $this->assertFalse($fields['all_active_admins_have_full_access']->getValue());
    }

    public function testDoesNotFlagASingleAdminAsLackingSeparation(): void
    {
        $factory = $this->userCollectionFactory([1], 0, 0, 0);
        $moduleList = $this->moduleList(tfaPresent: false, bypassPresent: false);
        $objectManager = $this->createMock(ObjectManagerInterface::class);
        $resourceConnection = $this->resourceConnectionWithRoleData([1], ['total' => 1, 'full_access' => 1]);

        $reporter = new AdminAccountsReporter(
            $factory,
            $moduleList,
            $objectManager,
            $resourceConnection,
            new Clock(),
            new Field(),
            new Section()
        );

        $fields = $reporter->getStatus()['general']->getFields();

        $this->assertFalse($fields['all_active_admins_have_full_access']->getValue());
    }

    public function testDeclaresTheWithout2faTrackableMetric(): void
    {
        $factory = $this->createMock(AdminUserCollectionFactory::class);
        $moduleList = $this->createMock(ModuleListInterface::class);
        $objectManager = $this->createMock(ObjectManagerInterface::class);

        $reporter = new AdminAccountsReporter(
            $factory,
            $moduleList,
            $objectManager,
            $this->resourceConnectionWithNoRoleData(),
            new Clock(),
            new Field(),
            new Section()
        );

        $metrics = $reporter->getTrackableMetrics();

        $this->assertSame('admin_accounts.without_2fa', $metrics[0]->getMetricKey());
        $this->assertSame('latest', $metrics[0]->getAggregation());
    }

    public function testDisabledTwoFactorModuleIsACriticalFinding(): void
    {
        $reporter = new AdminAccountsReporter(
            $this->userCollectionFactory([1], 0, 0, 0),
            $this->moduleList(tfaPresent: false, bypassPresent: false),
            $this->createMock(ObjectManagerInterface::class),
            $this->resourceConnectionWithNoRoleData(),
            new Clock(),
            new Field(),
            new Section()
        );

        $fields = $reporter->getStatus()['general']->getFields();
        $this->assertTrue($fields['two_factor_auth_disabled']->getValue());
        $this->assertSame('admin_accounts.two_factor_auth_disabled', $fields['two_factor_auth_disabled']->jsonSerialize()['metric_key']);

        $byKey = [];
        foreach ($reporter->getTrackableMetrics() as $metric) {
            $byKey[$metric->getMetricKey()] = $metric;
        }
        $this->assertSame('critical', $byKey['admin_accounts.two_factor_auth_disabled']->getSeverity());
    }

    public function testReportsStaleLoginsAndStalePasswords(): void
    {
        $now = time();
        $select = $this->createMock(Select::class);
        $select->method('from')->willReturnSelf();
        $select->method('where')->willReturnSelf();
        $select->method('group')->willReturnSelf();
        $connection = $this->createMock(AdapterInterface::class);
        $connection->method('select')->willReturn($select);
        $connection->method('fetchCol')->willReturn([]);
        $connection->method('fetchRow')->willReturn(['total' => 0, 'full_access' => 0]);
        // First fetchPairs: MAX(last_updated) per user; second: active users' creation dates.
        $connection->method('fetchPairs')->willReturnOnConsecutiveCalls(
            [1 => $now - 400 * 86400, 2 => $now - 10 * 86400],
            [
                1 => gmdate('Y-m-d H:i:s', $now - 800 * 86400),
                2 => gmdate('Y-m-d H:i:s', $now - 800 * 86400),
                3 => gmdate('Y-m-d H:i:s', $now - 500 * 86400),
                4 => gmdate('Y-m-d H:i:s', $now - 5 * 86400),
            ]
        );
        $resourceConnection = $this->createMock(ResourceConnection::class);
        $resourceConnection->method('getConnection')->willReturn($connection);
        $resourceConnection->method('getTableName')->willReturnArgument(0);

        $reporter = new AdminAccountsReporter(
            $this->userCollectionFactory([1, 2, 3, 4], 0, 0, 0, staleLogins: 2),
            $this->moduleList(tfaPresent: false, bypassPresent: false),
            $this->createMock(ObjectManagerInterface::class),
            $resourceConnection,
            new Clock(),
            new Field(),
            new Section()
        );

        $fields = $reporter->getStatus()['general']->getFields();

        $this->assertSame(2, $fields['stale_logins_90d']->getValue());
        // User 1 (changed 400d ago) and user 3 (no history, created 500d ago) are stale; 2 and 4 are not.
        $this->assertSame(2, $fields['stale_passwords']->getValue());
    }

    public function testDeclaresTheTripwireTrackableMetrics(): void
    {
        $factory = $this->createMock(AdminUserCollectionFactory::class);
        $moduleList = $this->createMock(ModuleListInterface::class);
        $objectManager = $this->createMock(ObjectManagerInterface::class);

        $reporter = new AdminAccountsReporter(
            $factory,
            $moduleList,
            $objectManager,
            $this->resourceConnectionWithNoRoleData(),
            new Clock(),
            new Field(),
            new Section()
        );

        $metrics = $reporter->getTrackableMetrics();
        $byKey = [];
        foreach ($metrics as $metric) {
            $byKey[$metric->getMetricKey()] = $metric;
        }

        $this->assertCount(8, $metrics);
        // The 2FA-bypass finding: alerts (critical) while its bool field is true.
        $this->assertArrayHasKey('admin_accounts.two_factor_auth_bypass_detected', $byKey);
        $this->assertSame('critical', $byKey['admin_accounts.two_factor_auth_bypass_detected']->getSeverity());
        $this->assertSame('eq', $byKey['admin_accounts.two_factor_auth_bypass_detected']->getDefaultOperator());
        $this->assertArrayHasKey('admin_accounts.recent_failed_logins_24h', $byKey);
        $this->assertSame(2, $byKey['admin_accounts.recent_failed_logins_24h']->getDefaultThreshold());
        $this->assertArrayHasKey('admin_accounts.new_admins_24h', $byKey);
        $this->assertSame(0, $byKey['admin_accounts.new_admins_24h']->getDefaultThreshold());
        $this->assertArrayHasKey('admin_accounts.dormant_accounts', $byKey);
        $this->assertSame(3, $byKey['admin_accounts.dormant_accounts']->getDefaultThreshold());
    }
}
