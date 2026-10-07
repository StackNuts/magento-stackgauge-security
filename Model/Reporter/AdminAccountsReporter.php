<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Reporter;

use Magento\Framework\App\ResourceConnection;
use Magento\Framework\DB\Sql\Expression;
use Magento\Framework\Module\ModuleListInterface;
use Magento\Framework\ObjectManagerInterface;
use Magento\TwoFactorAuth\Api\TfaInterface;
use Magento\User\Model\ResourceModel\User\CollectionFactory as AdminUserCollectionFactory;
use StackNuts\StackGauge\Api\DeclaresCadenceInterface;
use StackNuts\StackGauge\Api\DeclaresSectionInterface;
use StackNuts\StackGauge\Api\Field\Field;
use StackNuts\StackGauge\Api\MetricCatalogInterface;
use StackNuts\StackGauge\Api\MetricDefinition;
use StackNuts\StackGauge\Api\ReporterInterface;
use StackNuts\StackGauge\Api\Section\Section;
use StackNuts\StackGauge\Model\Reporter\Concern\DailyCadenceTrait;
use StackNuts\StackGauge\Model\Reporter\Concern\SecuritySectionTrait;
use StackNuts\StackGauge\Model\Util\Clock;
use Throwable;

/**
 * Admin account hygiene: lockouts, recent failed logins, newly-created admins, and
 * two-factor enrollment coverage - the account-takeover signals a store's own admin grid
 * never surfaces as a single health check.
 *
 * "Recent failed logins" and "new admins" only ever look back 24h, so a compromise that's
 * already a few days old won't show here - this is a tripwire for active attacks, not an
 * audit log.
 *
 * Whether 2FA is genuinely *enforced* is harder to pin down than it looks:
 * TfaInterface::isEnabled() unconditionally returns true in current Magento/Mage-OS versions
 * whenever the module exists at all, regardless of any real on/off switch - it is not a
 * usable signal. The one bypass mechanism actually in common use is a dev-convenience module
 * (MarkShust_DisableTwoFactorAuth, bundled with the popular Mark Shust Docker Magento setup)
 * that plugs TfaSession::isGranted() to always grant - its own author's docblock says
 * explicitly "always keep 2FA enabled within production environments." Detecting that one
 * module's presence is a narrower signal than tracing the live plugin list for anything
 * intercepting that method, but it catches the mechanism that's actually out there, which
 * isEnabled() alone cannot.
 */
class AdminAccountsReporter implements
    ReporterInterface,
    DeclaresCadenceInterface,
    DeclaresSectionInterface,
    MetricCatalogInterface
{
    use DailyCadenceTrait;
    use SecuritySectionTrait;

    private const SCHEMA_VERSION = '1.1';
    private const METRIC_WITHOUT_2FA = 'admin_accounts.without_2fa';

    /**
     * A known dev-convenience module that neuters 2FA enforcement regardless of
     * TfaInterface::isEnabled() - see this class's own docblock.
     */
    private const TFA_BYPASS_MODULE = 'MarkShust_DisableTwoFactorAuth';

    /**
     * @param AdminUserCollectionFactory $adminUserCollectionFactory
     * @param ModuleListInterface $moduleList
     * @param ObjectManagerInterface $objectManager Only used to lazily resolve
     *     Magento\TwoFactorAuth\Api\TfaInterface - that module isn't a composer dependency
     *     of this one (it isn't present on every supported Magento edition/version), so it
     *     can't be a constructor-injected type without breaking stores that don't have it.
     * @param ResourceConnection $resourceConnection
     * @param Clock $clock
     * @param Field $field
     * @param Section $section
     */
    public function __construct(
        private readonly AdminUserCollectionFactory $adminUserCollectionFactory,
        private readonly ModuleListInterface $moduleList,
        private readonly ObjectManagerInterface $objectManager,
        private readonly ResourceConnection $resourceConnection,
        private readonly Clock $clock,
        private readonly Field $field,
        private readonly Section $section
    ) {
    }

    /**
     * Payload key for the admin-accounts reporter.
     */
    public function getName(): string
    {
        return 'admin_accounts';
    }

    /**
     * Human-readable label for the admin-accounts reporter block.
     */
    public function getLabel(): string
    {
        return 'Admin Accounts';
    }

    /**
     * One-line summary of what the admin-accounts reporter covers, shown on the dashboard alongside the label.
     */
    public function getDescription(): string
    {
        return 'Admin account counts, lockouts, recent failed logins, new/dormant accounts, '
            . 'role separation, and two-factor enrollment.';
    }

    /**
     * Schema version for this reporter's payload shape.
     */
    public function getSchemaVersion(): string
    {
        return self::SCHEMA_VERSION;
    }

    /**
     * Reports admin account counts, lockouts, 24h failed-login and new-account signals, and 2FA enrollment coverage.
     */
    public function getStatus(): array
    {
        $activeAdminIds = $this->adminUserCollectionFactory->create()
            ->addFieldToFilter('is_active', 1)
            ->getAllIds();
        $totalActive = count($activeAdminIds);

        $now = $this->clock->now()->format('Y-m-d H:i:s');
        $windowStart = $this->clock->now()->modify('-24 hours')->format('Y-m-d H:i:s');

        $lockedAccounts = $this->adminUserCollectionFactory->create()
            ->addFieldToFilter('lock_expires', ['notnull' => true])
            ->addFieldToFilter('lock_expires', ['gt' => $now])
            ->getSize();

        // failures_num/first_failure track only the *current* failure streak (reset on a
        // successful login), not a full attempt log - this counts accounts currently mid-streak
        // whose streak started within the window, which is the closest proxy the admin_user
        // table itself can give without a dedicated login-attempt audit table.
        $recentFailedLogins = $this->adminUserCollectionFactory->create()
            ->addFieldToFilter('failures_num', ['gt' => 0])
            ->addFieldToFilter('first_failure', ['gteq' => $windowStart])
            ->getSize();

        $newAdmins = $this->adminUserCollectionFactory->create()
            ->addFieldToFilter('created', ['gteq' => $windowStart])
            ->getSize();

        // No age window, deliberately - an attacker who creates a backdoor account and then
        // waits before using it would already be outside the 24h new-account tripwire above.
        // "Active but never logged in" has no legitimate reason to persist indefinitely.
        $dormantAccounts = $this->adminUserCollectionFactory->create()
            ->addFieldToFilter('is_active', 1)
            ->addFieldToFilter('logdate', ['null' => true])
            ->getSize();

        $roleStats = $this->fetchAdminRoleStats();
        // Only meaningful with 2+ admins - one admin necessarily has full access to everything,
        // and that's not a lack of separation of duties, just the only role there is.
        $allActiveAdminsHaveFullAccess = $roleStats['total'] > 1 && $roleStats['full_access'] === $roleStats['total'];

        $tfa = $this->resolveTwoFactorAuth();
        $bypassDetected = $this->moduleList->has(self::TFA_BYPASS_MODULE);
        // "Active" means present AND not known to be neutered - not just isEnabled(), which
        // (see this class's own docblock) returns true regardless of real enforcement state.
        $tfaActive = $tfa !== null && !$bypassDetected;
        // 0, not $totalActive, when 2FA isn't genuinely active: a store that's made a
        // deliberate choice not to use 2FA (or whose enforcement is currently bypassed) isn't
        // "missing enrollment" by this metric's definition - that state is already its own
        // separate, uncolored signal via two_factor_auth_enabled/bypass_detected above.
        // Counting every account here would make this metric default to alerting on nearly
        // every Open Source store that simply doesn't use the feature.
        $accountsWithout2fa = $tfaActive
            ? $this->countAccountsWithoutTwoFactor($tfa, $activeAdminIds)
            : 0;

        return ['general' => $this->section->facts('general', 'General', $this->getDescription(), [
            'total_admin_accounts' => $this->field->number('Total Admin Accounts', $totalActive),
            'locked_accounts' => $this->field->number(
                'Locked Accounts',
                $lockedAccounts,
                severity: $this->field->severityIf($lockedAccounts > 0)
            ),
            'accounts_with_recent_failed_logins_24h' => $this->field->number(
                'Accounts With Recent Failed Logins (24h)',
                $recentFailedLogins,
                severity: $this->field->severityIf($recentFailedLogins > 0)
            ),
            'new_admin_accounts_24h' => $this->field->number(
                'New Admin Accounts (24h)',
                $newAdmins,
                severity: $this->field->severityIf($newAdmins > 0)
            ),
            'dormant_active_accounts' => $this->field->number(
                'Dormant Active Accounts',
                $dormantAccounts,
                severity: $this->field->severityIf($dormantAccounts > 0)
            ),
            'all_active_admins_have_full_access' => $this->field->bool(
                'All Active Admins Have Full Access',
                $allActiveAdminsHaveFullAccess,
                criticalWhen: true
            ),
            'two_factor_auth_enabled' => $this->field->bool('Two-Factor Auth Enabled', $tfaActive),
            'two_factor_auth_bypass_detected' => $this->field->bool(
                'Two-Factor Auth Bypass Detected',
                $bypassDetected,
                criticalWhen: true
            ),
            'admin_accounts_without_2fa' => $this->field->trackableNumber(
                'Admin Accounts Without 2FA',
                $accountsWithout2fa,
                self::METRIC_WITHOUT_2FA,
                MetricDefinition::AGGREGATION_LATEST,
                severity: $this->field->severityIf($accountsWithout2fa > 0)
            ),
        ])];
    }

    /**
     * Alertable metric for the admin-accounts reporter: active admins who haven't completed
     * 2FA enrollment, including every account when 2FA is off entirely (see getStatus()'s own
     * comment on that choice).
     */
    public function getTrackableMetrics(): array
    {
        return [
            // Window comfortably outlives the ~24h gap between daily-cadence samples. Any
            // account without 2FA is worth flagging (threshold 0) - this is a posture metric,
            // not a count where some non-zero baseline is normal.
            new MetricDefinition(
                self::METRIC_WITHOUT_2FA,
                'Admin Accounts: Without 2FA',
                MetricDefinition::AGGREGATION_LATEST,
                MetricDefinition::OPERATOR_GT,
                0,
                1500,
                null,
                description: '{value} admin accounts have no two-factor authentication, above the limit of {threshold}.',
                impact: 'Accounts without a second factor are an easier route to a takeover.'
            ),
        ];
    }

    /**
     * Counts active admin accounts, and how many of them hold a role with full ("all
     * resources") access - via authorization_role/authorization_rule directly rather than
     * Magento's ACL service classes, since this needs an aggregate across every admin at once,
     * not a per-user permission check. A role has full access when it (or, for a per-user role
     * row, its parent group role) carries an authorization_rule granting "Magento_Backend::all"
     * - the same resource Magento's own seeded "Administrators" role uses, and the standard way
     * a role ends up with blanket access rather than a specific ACL tree. A lookup failure
     * (e.g. this Magento version's authorization schema differs) is treated as "nothing to
     * report" rather than a reporter failure.
     *
     * @return array{total: int, full_access: int}
     */
    private function fetchAdminRoleStats(): array
    {
        try {
            $connection = $this->resourceConnection->getConnection();
            $roleTable = $this->resourceConnection->getTableName('authorization_role');
            $ruleTable = $this->resourceConnection->getTableName('authorization_rule');
            $adminUserTable = $this->resourceConnection->getTableName('admin_user');

            $fullAccessRoleIds = $connection->fetchCol(
                $connection->select()
                    ->distinct()
                    ->from($ruleTable, ['role_id'])
                    ->where('resource_id = ?', 'Magento_Backend::all')
                    ->where('permission = ?', 'allow')
            );

            $fullAccessCaseSql = $fullAccessRoleIds === []
                ? '0'
                : 'COUNT(DISTINCT CASE WHEN ar.parent_id IN ('
                    . implode(',', array_map('intval', $fullAccessRoleIds)) . ') THEN au.user_id END)';

            $select = $connection->select()
                ->from(['au' => $adminUserTable], [])
                ->joinInner(
                    ['ar' => $roleTable],
                    "ar.user_id = au.user_id AND ar.role_type = 'U' AND ar.user_type = 2",
                    []
                )
                ->where('au.is_active = ?', 1)
                ->columns([
                    'total' => new Expression('COUNT(DISTINCT au.user_id)'),
                    'full_access' => new Expression($fullAccessCaseSql),
                ]);

            $row = $connection->fetchRow($select);

            return ['total' => (int)($row['total'] ?? 0), 'full_access' => (int)($row['full_access'] ?? 0)];
        } catch (Throwable) {
            return ['total' => 0, 'full_access' => 0];
        }
    }

    /**
     * Lazily resolves Magento\TwoFactorAuth\Api\TfaInterface, or null when that module isn't
     * installed/enabled on this store - see this class's own constructor docblock for why
     * this can't be a constructor-injected dependency.
     */
    private function resolveTwoFactorAuth(): ?TfaInterface
    {
        if (!$this->moduleList->has('Magento_TwoFactorAuth') || !interface_exists(TfaInterface::class)) {
            return null;
        }

        try {
            return $this->objectManager->get(TfaInterface::class);
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Counts active admins who still have at least one provider left to activate - i.e. who
     * haven't completed 2FA enrollment. A per-user lookup failure counts as "not confirmed
     * enrolled" rather than being silently skipped, so a read error can't understate the count.
     *
     * @param TfaInterface $tfa
     * @param list<int> $activeAdminIds
     */
    private function countAccountsWithoutTwoFactor(TfaInterface $tfa, array $activeAdminIds): int
    {
        $count = 0;

        foreach ($activeAdminIds as $adminId) {
            try {
                if ($tfa->getProvidersToActivate((int)$adminId) !== []) {
                    $count++;
                }
            } catch (Throwable) {
                $count++;
            }
        }

        return $count;
    }
}
