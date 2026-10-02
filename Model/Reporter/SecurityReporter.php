<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Reporter;

use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\App\MaintenanceMode;
use Magento\Framework\Module\ModuleListInterface;
use StackNuts\StackGauge\Api\DeclaresCadenceInterface;
use StackNuts\StackGauge\Api\DeclaresSectionInterface;
use StackNuts\StackGauge\Api\Field\ArrayField;
use StackNuts\StackGauge\Api\Field\Field;
use StackNuts\StackGauge\Api\ReporterInterface;
use StackNuts\StackGauge\Api\Section\Section;
use StackNuts\StackGauge\Model\Reporter\Concern\DailyCadenceTrait;
use StackNuts\StackGauge\Model\Reporter\Concern\PlatformSectionTrait;
use StackNuts\StackGauge\Model\StorefrontProbe;
use StackNuts\StackGaugeSecurity\Model\Util\CoreFileTamperScanner;
use StackNuts\StackGaugeSecurity\Model\Util\FilesystemExposureScanner;
use StackNuts\StackGaugeSecurity\Model\Util\PubExecutableScanner;

class SecurityReporter implements ReporterInterface, DeclaresCadenceInterface, DeclaresSectionInterface
{
    use DailyCadenceTrait;
    use PlatformSectionTrait;

    private const SCHEMA_VERSION = '1.0';
    private const DEFAULT_ADMIN_PATH = 'admin';

    /**
     * @param DeploymentConfig $deploymentConfig
     * @param MaintenanceMode $maintenanceMode
     * @param ModuleListInterface $moduleList
     * @param StorefrontProbe $storefrontProbe
     * @param FilesystemExposureScanner $filesystemExposureScanner
     * @param PubExecutableScanner $pubExecutableScanner
     * @param CoreFileTamperScanner $coreFileTamperScanner
     * @param Field $field
     * @param Section $section
     */
    public function __construct(
        private readonly DeploymentConfig $deploymentConfig,
        private readonly MaintenanceMode $maintenanceMode,
        private readonly ModuleListInterface $moduleList,
        private readonly StorefrontProbe $storefrontProbe,
        private readonly FilesystemExposureScanner $filesystemExposureScanner,
        private readonly PubExecutableScanner $pubExecutableScanner,
        private readonly CoreFileTamperScanner $coreFileTamperScanner,
        private readonly Field $field,
        private readonly Section $section
    ) {
    }

    /**
     * Payload key for the security reporter.
     */
    public function getName(): string
    {
        return 'security';
    }

    /**
     * Human-readable label for the security reporter block.
     */
    public function getLabel(): string
    {
        return 'Security';
    }

    /**
     * One-line summary of what the security reporter covers, shown on the dashboard alongside the label.
     */
    public function getDescription(): string
    {
        return 'Admin path/maintenance-mode/sample-data state, exposed sensitive paths, VCS/backup/rogue-PHP '
            . 'files in the webroot, executable files under pub/media or pub/static, and '
            . 'anomalous core-file modification times.';
    }

    /**
     * Schema version for this reporter's payload shape.
     */
    public function getSchemaVersion(): string
    {
        return self::SCHEMA_VERSION;
    }

    /**
     * Reports admin path/maintenance-mode/sample-data state, plus exposed sensitive paths.
     *
     * Whether the admin path is still the default, maintenance-mode state, any installed
     * sample-data modules, and any sensitive path exposed from the public storefront.
     */
    public function getStatus(): array
    {
        $sampleDataModules = array_values(array_filter(
            array_keys($this->moduleList->getAll()),
            static fn (string $name): bool => str_contains($name, 'SampleData')
        ));
        $filesystemFindings = $this->filesystemExposureScanner->scan();
        $pubExecutableFiles = $this->pubExecutableScanner->scan();
        $tamperedCoreFiles = $this->coreFileTamperScanner->scan();

        return [
            'general' => $this->section->facts('general', 'General', '', [
                // Deliberately a boolean, not the actual admin path string - sending every
                // client's real (deliberately obscured) admin URL to a third-party dashboard
                // would concentrate exactly the secret that obscurity is meant to protect.
                'is_default_admin_path' => $this->field->bool(
                    'Is Default Admin Path',
                    $this->getAdminFrontName() === self::DEFAULT_ADMIN_PATH,
                    criticalWhen: true
                ),
                'maintenance_mode' => $this->field->bool(
                    'Maintenance Mode',
                    $this->maintenanceMode->isOn(),
                    criticalWhen: true
                ),
                'sample_data_present' => $this->field->bool(
                    'Sample Data Present',
                    $sampleDataModules !== [],
                    criticalWhen: true
                ),
                'filesystem_exposure_detected' => $this->field->bool(
                    'Filesystem Exposure Detected',
                    $filesystemFindings !== [],
                    criticalWhen: true
                ),
                'pub_executable_files_detected' => $this->field->bool(
                    'Executable Files In pub/media Or pub/static Detected',
                    $pubExecutableFiles !== [],
                    criticalWhen: true
                ),
                // Not criticalWhen: true - this is a soft heuristic (see CoreFileTamperScanner's
                // own docblock), not proof of compromise, so "warning" rather than the same
                // severity as a confirmed exposed file.
                'core_file_mtime_drift_count' => $this->field->number(
                    'Core Files With Anomalous mtime Drift',
                    count($tamperedCoreFiles),
                    severity: $tamperedCoreFiles !== [] ? Field::SEVERITY_WARNING : Field::SEVERITY_OK
                ),
            ]),
            'sample_data_modules' => $this->section->table('sample_data_modules', 'Sample Data Modules', '', array_map(
                fn (string $name) => $this->field->array($name, [
                    'module' => $this->field->varchar('Module', $name),
                ]),
                $sampleDataModules
            ), keyName: 'module'),
            'exposed_paths' => $this->section->table(
                'exposed_paths',
                'Exposed Paths',
                'Sensitive paths that should 404 from the public storefront but didn\'t, '
                    . 'checked via a self-probe from this server.',
                $this->exposedPathFields()
            ),
            'filesystem_findings' => $this->section->table(
                'filesystem_findings',
                'Filesystem Exposure Findings',
                'VCS metadata, leftover backup files, and unrecognized PHP files found directly '
                    . 'in the project root or pub/ - see FilesystemExposureScanner.',
                $this->filesystemFindingFields($filesystemFindings),
                // Two different findings (e.g. a ".git" directory in both root and pub/) can
                // legitimately share the same "name" - skip the duplicate-row check rather than
                // have that throw as if it were a reporter bug.
                keyName: 'row_identity_not_checked'
            ),
            'pub_executable_files' => $this->section->table(
                'pub_executable_files',
                'Executable Files In pub/media Or pub/static',
                'Files with an executable extension (.php, .phtml, .phar, ...) found under '
                    . 'pub/media or pub/static, where only images/CSS/JS/other static assets '
                    . 'should ever exist - see PubExecutableScanner.',
                $this->pubExecutableFileFields($pubExecutableFiles)
            ),
            'core_file_mtime_drift' => $this->section->table(
                'core_file_mtime_drift',
                'Core Files With Anomalous mtime Drift',
                'A soft heuristic, not proof of tampering: PHP files under vendor/magento/* or '
                    . 'vendor/mage-os/* whose modified time drifts more than 48h newer than the '
                    . 'rest of their own package - see CoreFileTamperScanner for why this can be '
                    . 'beaten by a plain `touch` and what it\'s actually good for.',
                $this->coreFileTamperFields($tamperedCoreFiles)
            ),
        ];
    }

    /**
     * Builds one row per match from CoreFileTamperScanner::scan().
     *
     * See its own docblock for the package/path/drift_hours shape each entry has.
     *
     * @param list<array> $matches
     * @return list<ArrayField>
     */
    private function coreFileTamperFields(array $matches): array
    {
        return array_map(
            fn (array $match) => $this->field->array($match['package'] . '/' . $match['path'], [
                'package' => $this->field->varchar('Package', $match['package']),
                'path' => $this->field->varchar('Path', $match['path']),
                'drift_hours' => $this->field->number('Drift (hours)', $match['drift_hours']),
            ]),
            $matches
        );
    }

    /**
     * Builds one row per match from PubExecutableScanner::scan().
     *
     * See its own docblock for the directory/path shape each entry has.
     *
     * @param list<array> $matches
     * @return list<ArrayField>
     */
    private function pubExecutableFileFields(array $matches): array
    {
        return array_map(
            fn (array $match) => $this->field->array($match['directory'] . '/' . $match['path'], [
                'directory' => $this->field->varchar('Directory', $match['directory']),
                'path' => $this->field->varchar('Path', $match['path']),
            ]),
            $matches
        );
    }

    /**
     * Builds one row per finding from FilesystemExposureScanner::scan().
     *
     * See its own docblock for the location/type/name shape each entry has.
     *
     * @param list<array> $findings
     * @return list<ArrayField>
     */
    private function filesystemFindingFields(array $findings): array
    {
        return array_map(
            fn (array $finding) => $this->field->array($finding['name'], [
                'location' => $this->field->varchar('Location', $finding['location']),
                'type' => $this->field->varchar('Type', $finding['type']),
                'name' => $this->field->varchar('Name', $finding['name']),
            ]),
            $findings
        );
    }

    /**
     * Builds one row per path StorefrontProbe checked, via a self-probe from this server.
     *
     * @return list<ArrayField>
     */
    private function exposedPathFields(): array
    {
        $rows = [];

        foreach ($this->storefrontProbe->checkExposedPaths() as $path => $exposed) {
            $rows[] = $this->field->array($path, [
                'path' => $this->field->varchar('Path', $path),
                'exposed' => $this->field->bool('Exposed', $exposed, criticalWhen: true),
            ]);
        }

        return $rows;
    }

    /**
     * Resolves the configured admin frontName, falling back to DEFAULT_ADMIN_PATH when unset.
     */
    private function getAdminFrontName(): string
    {
        return (string)($this->deploymentConfig->get('backend/frontName') ?? self::DEFAULT_ADMIN_PATH);
    }
}
