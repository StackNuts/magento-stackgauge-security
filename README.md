# StackNuts StackGaugeSecurity

Security-posture checks for [StackNuts StackGauge](https://github.com/StackNuts/magento-stackgauge),
split into their own module.

## Why a separate module

Not every StackGauge install wants this. A lot of agencies already have dedicated security
scanning in place - Sansec, host-level malware scanning, their own tooling - and running a
second, overlapping set of filesystem walks and content checks on every client site is wasted
cost for no benefit. StackGauge's own extension architecture already supports third-party
reporters cleanly (see its README's "Pluggable reporters" section, and
`StackNuts_StackGaugeCloudflareCache` for a working example), so splitting this out costs
nothing architecturally and lets anyone who doesn't want it just not install it.

## Installation

```bash
composer require stacknuts/magento-stackgauge-security
bin/magento module:enable StackNuts_StackGaugeSecurity
bin/magento setup:upgrade
```

Requires `stacknuts/magento-stackgauge` (StackGauge core) to already be installed - this
module only contributes reporters to its `ReporterPool`, it has no functionality of its own
outside that.

## What it contributes

| Reporter | Payload key | What it covers |
|---|---|---|
| `SecurityReporter` | `security` | Admin path/maintenance-mode/sample-data state, sensitive paths exposed from the public storefront, VCS/backup/rogue-PHP files in the webroot, executable files under `pub/media`/`pub/static`, and anomalous core-file modification times |
| `AdminAccountsReporter` | `admin_accounts` | Admin account counts, lockouts, failed-login/new-account/dormant-account signals, admin role separation, two-factor enrollment coverage |
| `ConfigHygieneReporter` | `config_hygiene` | Dev/debug settings (template hints, CSS/JS minify, static signing) left in a risky production state |
| `ContentSignatureReporter` | `content_signatures` | CMS block/page content, admin-editable HTML/JS config values, and suspicious `pub/` files checked against a hand-curated set of known webshell and Magecart-skimmer content signatures |

`SecurityReporter` never reports the actual admin path, only whether it's still the Magento
default - the real path stays private to your store.

`AdminAccountsReporter` only ever reports counts - no usernames, emails, or other identifying
detail about any admin account ever leaves your store.

## What `SecurityReporter` checks, in detail

- **`exposed_paths`** - a daily self-probe (curling this store's own homepage, via
  `StackNuts\StackGauge\Model\StorefrontProbe::checkExposedPaths()`) for a fixed list of
  sensitive paths (`.git/HEAD`, `composer.lock`, `app/etc/env.php`, etc.) that should 404 from
  the public storefront but sometimes don't - usually because the webserver's docroot is
  misconfigured to the project root instead of `pub/`.
- **`filesystem_findings`** - VCS metadata (`.git`, `.svn`, ...), leftover backup/dump files,
  and PHP files outside Magento's known `pub/` entrypoints, found directly in the project root
  or `pub/` (shallow, non-recursive - see `Model\Util\FilesystemExposureScanner`).
- **`pub_executable_files`** - `.php`/`.phtml`/`.phar` files found anywhere under `pub/media`
  or `pub/static`, where only images/CSS/JS/other static assets should ever exist - the classic
  post-upload-vulnerability webshell drop location, and one nginx in particular often doesn't
  block execution of even when Magento's own `pub/media/.htaccess` says to. Bounded: never
  follows symlinks, caps total files visited and max depth, and prunes known-huge image-cache
  subdirectories before descending into them - see `Model\Util\PubExecutableScanner`.
- **`core_file_mtime_drift`** - PHP files under `vendor/magento/*` or `vendor/mage-os/*` whose
  modified time drifts more than 48h newer than the rest of their own package - `composer
  install` writes every file in a package at roughly the same time, so one file sitting days
  newer than its siblings means something touched it directly afterward. This is a soft
  heuristic, not proof of tampering (a plain `touch` defeats it, and a legitimate hand-applied
  security patch looks identical to tampering by this signal alone) - reported as a warning,
  not critical, for exactly that reason. See `Model\Util\CoreFileTamperScanner`.

## What `ContentSignatureReporter` checks, in detail

- **`content_signature_matches`** - CMS block/page content, admin-editable HTML/JS config
  values (`design/head/includes` and similar known injection points, plus any `core_config_data`
  value containing a `<script` tag or `http-equiv` override), and files
  `Model\Util\PubExecutableScanner` already flagged, each checked against a bundled signature
  set (`etc/signatures.json`) of known webshell and Magecart-skimmer content patterns. CMS
  content is read directly from `cms_block`/`cms_page` via keyset-paginated batches rather than
  the repository API, so a large content library is scanned in full without a memory spike or
  a single flat page-size cutoff - see `Model\ContentSource\CmsContentSource` for why.
- Never reports the matched content itself, only the location (a block/page identifier, config
  path, or file path) and which signature matched - a confirmed-malicious payload never travels
  through the report pipeline, even to StackNuts' own dashboard.
- **`content_scan_truncated`** - true only if the CMS content library is large enough to hit the
  scan's safety backstop (20,000 rows per table); real stores essentially never hit this, and
  it's surfaced rather than left silent if it ever does.
- The bundled signature set is currently a small, hand-curated starter list. A larger,
  community-reviewed set is planned as a future update to this module.

## Toggling individual checks

Every reporter above shows up automatically in StackGauge's own **Disabled Reporters** admin
field (Stores > Configuration > Advanced > StackGauge) - there's nothing to configure in this
module specifically. That field's options are derived from whatever's actually registered with
`ReporterPool`, built-in or contributed, so installing this module is the only step needed for
its reporters to become individually toggleable there too.

## Uninstall

```bash
bin/magento module:disable StackNuts_StackGaugeSecurity
composer remove stacknuts/magento-stackgauge-security
```

This module persists no state of its own - nothing for `module:uninstall` to clean up.

## License

PolyForm Shield License 1.0.0 - see [LICENSE](LICENSE).
