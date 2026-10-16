<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Util;

/**
 * Matches a signature set (see SignatureStore) against a map of named content strings - CMS
 * block/page bodies, a design config value, a PHP file's contents, whatever a caller collects.
 * Pure string/regex matching with no I/O of its own, deliberately: every content source
 * (filesystem, CMS repository, config) is a different concern with its own failure modes, so
 * those stay in their own collaborators and this class stays trivial to unit test.
 *
 * A signature only runs against content whose target matches one of the signature's declared
 * targets (see SignatureStore::getSignatures()'s "target" key) - a webshell signature never
 * runs against CMS content and vice versa, keeping false-positive surface area to exactly
 * what each signature was written against.
 *
 * Literal patterns are matched case-insensitively (`EVAL(` evades nothing); signatures that also
 * need to tolerate whitespace or comments between tokens are written as regexes with the `i` flag
 * and `\s*`. A wall-clock budget (MAX_SCAN_SECONDS, started by resetBudget() or the first scan())
 * bounds the total regex time across every source, as a backstop against a pathological pattern
 * run over many files - once spent, scan() returns nothing further and wasBudgetExceeded() is true.
 */
class ContentSignatureScanner
{
    private const PATTERN_TYPE_LITERAL = 'literal';
    private const PATTERN_TYPE_REGEX = 'regex';
    private const MAX_SCAN_SECONDS = 120.0;

    /**
     * @var float|null Microtime at which the current budget started, or null before the first scan.
     */
    private ?float $budgetStartedAt = null;

    private bool $budgetExceeded = false;

    /**
     * Ids of regex signatures that errored (most often PCRE's backtrack limit on a large body)
     * during any scan() so far - see getErroredSignatureIds().
     *
     * @var array<string, true>
     */
    private array $erroredSignatureIds = [];

    /**
     * Starts a fresh time budget and clears the exceeded flag - call at the start of each report run.
     */
    public function resetBudget(): void
    {
        $this->budgetStartedAt = microtime(true);
        $this->budgetExceeded = false;
    }

    /**
     * Whether the scan time budget ran out, so some content went unchecked.
     */
    public function wasBudgetExceeded(): bool
    {
        return $this->budgetExceeded;
    }

    /**
     * Whether the budget is spent (and records it) - callers walking many files can stop early.
     */
    public function isBudgetSpent(): bool
    {
        $this->budgetStartedAt ??= microtime(true);

        if (microtime(true) - $this->budgetStartedAt > self::MAX_SCAN_SECONDS) {
            $this->budgetExceeded = true;
        }

        return $this->budgetExceeded;
    }

    /**
     * Matches every signature targeting $target against each entry in $content.
     *
     * $signatures is SignatureStore::getSignatures()'s format (id, name, severity, target,
     * pattern_type, pattern).
     *
     * @param list<array> $signatures
     * @param string $target One of a signature's "target" values, e.g. "cms_content".
     * @param array $content Location label => content string, e.g. a CMS block identifier
     *     or a file path mapped to its body.
     * @return list<array>
     */
    public function scan(array $signatures, string $target, array $content): array
    {
        $applicable = array_values(array_filter(
            $signatures,
            static fn (array $signature): bool => in_array($target, $signature['target'] ?? [], true)
        ));

        if ($applicable === []) {
            return [];
        }

        $matches = [];

        foreach ($content as $location => $body) {
            if ($this->isBudgetSpent()) {
                break;
            }

            foreach ($applicable as $signature) {
                if ($this->matches($signature, $body)) {
                    $matches[] = [
                        'location' => $location,
                        'signature_id' => $signature['id'],
                        'name' => $signature['name'],
                        'severity' => $signature['severity'],
                    ];
                }
            }
        }

        return $matches;
    }

    /**
     * Signature ids whose regex failed to run (rather than simply not matching) in any scan()
     * so far. A failed preg_match() returns false, which would otherwise read exactly like
     * "no match" - a silent false negative on precisely the oversized, obfuscated content most
     * worth checking. Exposed so ContentSignatureReporter can report it.
     *
     * @return list<string>
     */
    public function getErroredSignatureIds(): array
    {
        return array_keys($this->erroredSignatureIds);
    }

    /**
     * Whether one signature matches $body.
     *
     * @param array $signature
     * @param string $body
     */
    private function matches(array $signature, string $body): bool
    {
        return match ($signature['pattern_type']) {
            self::PATTERN_TYPE_LITERAL => stripos($body, (string)$signature['pattern']) !== false,
            self::PATTERN_TYPE_REGEX => $this->regexMatches($signature, $body),
            default => false,
        };
    }

    /**
     * preg_match() for one regex signature, recording it in $erroredSignatureIds if it errors.
     *
     * @param array $signature
     * @param string $body
     */
    private function regexMatches(array $signature, string $body): bool
    {
        $result = preg_match($signature['pattern'], $body);

        if ($result === false) {
            $this->erroredSignatureIds[(string)$signature['id']] = true;
        }

        return $result === 1;
    }
}
