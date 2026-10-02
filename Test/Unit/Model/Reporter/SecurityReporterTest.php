<?php
declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Test\Unit\Model\Reporter;

use PHPUnit\Framework\TestCase;
use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\App\MaintenanceMode;
use Magento\Framework\Module\ModuleListInterface;
use StackNuts\StackGauge\Api\Field\Field;
use StackNuts\StackGauge\Api\Section\Section;
use StackNuts\StackGaugeSecurity\Model\Reporter\SecurityReporter;
use StackNuts\StackGauge\Model\StorefrontProbe;
use StackNuts\StackGaugeSecurity\Model\Util\CoreFileTamperScanner;
use StackNuts\StackGaugeSecurity\Model\Util\FilesystemExposureScanner;
use StackNuts\StackGaugeSecurity\Model\Util\PubExecutableScanner;

class SecurityReporterTest extends TestCase
{
    /**
     * @param list<array{location: string, type: string, name: string}> $findings
     * @param list<array{directory: string, path: string}> $pubExecutableMatches
     * @param list<array{package: string, path: string, drift_hours: int}> $coreFileTamperMatches
     */
    private function reporter(
        ModuleListInterface $moduleList,
        StorefrontProbe $storefrontProbe,
        array $findings = [],
        array $pubExecutableMatches = [],
        array $coreFileTamperMatches = []
    ): SecurityReporter {
        $deploymentConfig = $this->createMock(DeploymentConfig::class);
        $maintenance = $this->createMock(MaintenanceMode::class);
        $maintenance->method('isOn')->willReturn(false);
        $filesystemExposureScanner = $this->createMock(FilesystemExposureScanner::class);
        $filesystemExposureScanner->method('scan')->willReturn($findings);
        $pubExecutableScanner = $this->createMock(PubExecutableScanner::class);
        $pubExecutableScanner->method('scan')->willReturn($pubExecutableMatches);
        $coreFileTamperScanner = $this->createMock(CoreFileTamperScanner::class);
        $coreFileTamperScanner->method('scan')->willReturn($coreFileTamperMatches);

        return new SecurityReporter(
            $deploymentConfig,
            $maintenance,
            $moduleList,
            $storefrontProbe,
            $filesystemExposureScanner,
            $pubExecutableScanner,
            $coreFileTamperScanner,
            new Field(),
            new Section()
        );
    }

    public function testGetStatusReturnsSecurityInfo(): void
    {
        $moduleList = $this->createMock(ModuleListInterface::class);
        $moduleList->method('getAll')->willReturn([]);
        $storefrontProbe = $this->createMock(StorefrontProbe::class);
        $storefrontProbe->method('checkExposedPaths')->willReturn([]);

        $status = $this->reporter($moduleList, $storefrontProbe)->getStatus();
        $fields = $status['general']->getFields();

        $this->assertArrayHasKey('is_default_admin_path', $fields);
        $this->assertArrayHasKey('maintenance_mode', $fields);
        $this->assertArrayHasKey('exposed_paths', $status);
        $this->assertArrayHasKey('filesystem_findings', $status);
        $this->assertFalse($fields['filesystem_exposure_detected']->getValue());
    }

    public function testExposedPathsReflectTheStorefrontProbeResult(): void
    {
        $moduleList = $this->createMock(ModuleListInterface::class);
        $moduleList->method('getAll')->willReturn([]);
        $storefrontProbe = $this->createMock(StorefrontProbe::class);
        $storefrontProbe->method('checkExposedPaths')->willReturn([
            '.git/HEAD' => true,
            'composer.lock' => false,
        ]);

        $rows = $this->reporter($moduleList, $storefrontProbe)->getStatus()['exposed_paths']->getRows();

        $this->assertCount(2, $rows);
        $gitRow = $rows[0]->getValue();
        $this->assertSame('.git/HEAD', $gitRow['path']->getValue());
        $this->assertTrue($gitRow['exposed']->getValue());

        $composerRow = $rows[1]->getValue();
        $this->assertFalse($composerRow['exposed']->getValue());
    }

    public function testFilesystemFindingsAreReportedAndFlagTheSummaryBool(): void
    {
        $moduleList = $this->createMock(ModuleListInterface::class);
        $moduleList->method('getAll')->willReturn([]);
        $storefrontProbe = $this->createMock(StorefrontProbe::class);
        $storefrontProbe->method('checkExposedPaths')->willReturn([]);

        $findings = [
            ['location' => 'pub', 'type' => 'vcs_directory', 'name' => '.git'],
            ['location' => 'root', 'type' => 'backup_file', 'name' => 'backup.sql'],
        ];

        $status = $this->reporter($moduleList, $storefrontProbe, $findings)->getStatus();

        $this->assertTrue($status['general']->getFields()['filesystem_exposure_detected']->getValue());

        $rows = $status['filesystem_findings']->getRows();
        $this->assertCount(2, $rows);
        $first = $rows[0]->getValue();
        $this->assertSame('pub', $first['location']->getValue());
        $this->assertSame('vcs_directory', $first['type']->getValue());
        $this->assertSame('.git', $first['name']->getValue());
    }

    /**
     * Two findings sharing the same "name" (a ".git" directory in both root and pub/, say)
     * must not be treated as a reporter bug by the table's default duplicate-row check.
     */
    public function testDoesNotThrowWhenTwoFindingsShareTheSameName(): void
    {
        $moduleList = $this->createMock(ModuleListInterface::class);
        $moduleList->method('getAll')->willReturn([]);
        $storefrontProbe = $this->createMock(StorefrontProbe::class);
        $storefrontProbe->method('checkExposedPaths')->willReturn([]);

        $findings = [
            ['location' => 'root', 'type' => 'vcs_directory', 'name' => '.git'],
            ['location' => 'pub', 'type' => 'vcs_directory', 'name' => '.git'],
        ];

        $rows = $this->reporter($moduleList, $storefrontProbe, $findings)->getStatus()['filesystem_findings']
            ->getRows();

        $this->assertCount(2, $rows);
    }

    public function testPubExecutableFilesAreReportedAndFlagTheSummaryBool(): void
    {
        $moduleList = $this->createMock(ModuleListInterface::class);
        $moduleList->method('getAll')->willReturn([]);
        $storefrontProbe = $this->createMock(StorefrontProbe::class);
        $storefrontProbe->method('checkExposedPaths')->willReturn([]);

        $matches = [
            ['directory' => 'pub/media', 'path' => 'wysiwyg/shell.php'],
        ];

        $status = $this->reporter($moduleList, $storefrontProbe, pubExecutableMatches: $matches)->getStatus();

        $this->assertTrue($status['general']->getFields()['pub_executable_files_detected']->getValue());

        $rows = $status['pub_executable_files']->getRows();
        $this->assertCount(1, $rows);
        $row = $rows[0]->getValue();
        $this->assertSame('pub/media', $row['directory']->getValue());
        $this->assertSame('wysiwyg/shell.php', $row['path']->getValue());
    }

    public function testPubExecutableFilesSummaryBoolIsFalseWhenNothingFound(): void
    {
        $moduleList = $this->createMock(ModuleListInterface::class);
        $moduleList->method('getAll')->willReturn([]);
        $storefrontProbe = $this->createMock(StorefrontProbe::class);
        $storefrontProbe->method('checkExposedPaths')->willReturn([]);

        $status = $this->reporter($moduleList, $storefrontProbe)->getStatus();

        $this->assertFalse($status['general']->getFields()['pub_executable_files_detected']->getValue());
        $this->assertSame([], $status['pub_executable_files']->getRows());
    }

    public function testCoreFileMtimeDriftIsReportedAsAWarningNotCritical(): void
    {
        $moduleList = $this->createMock(ModuleListInterface::class);
        $moduleList->method('getAll')->willReturn([]);
        $storefrontProbe = $this->createMock(StorefrontProbe::class);
        $storefrontProbe->method('checkExposedPaths')->willReturn([]);

        $matches = [
            ['package' => 'magento/module-catalog', 'path' => 'Model/Product.php', 'drift_hours' => 72],
        ];

        $status = $this->reporter($moduleList, $storefrontProbe, coreFileTamperMatches: $matches)->getStatus();

        $generalFields = $status['general']->getFields();
        $this->assertSame(1, $generalFields['core_file_mtime_drift_count']->getValue());
        $this->assertSame('warning', $generalFields['core_file_mtime_drift_count']->jsonSerialize()['severity']);

        $rows = $status['core_file_mtime_drift']->getRows();
        $this->assertCount(1, $rows);
        $row = $rows[0]->getValue();
        $this->assertSame('magento/module-catalog', $row['package']->getValue());
        $this->assertSame('Model/Product.php', $row['path']->getValue());
        $this->assertSame(72, $row['drift_hours']->getValue());
    }

    public function testCoreFileMtimeDriftIsCleanWhenNothingFound(): void
    {
        $moduleList = $this->createMock(ModuleListInterface::class);
        $moduleList->method('getAll')->willReturn([]);
        $storefrontProbe = $this->createMock(StorefrontProbe::class);
        $storefrontProbe->method('checkExposedPaths')->willReturn([]);

        $status = $this->reporter($moduleList, $storefrontProbe)->getStatus();

        $this->assertSame(0, $status['general']->getFields()['core_file_mtime_drift_count']->getValue());
        $this->assertSame([], $status['core_file_mtime_drift']->getRows());
    }
}
