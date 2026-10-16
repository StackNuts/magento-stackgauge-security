<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Util;

/**
 * Structural check on a decoded signature set, applied both before a fetched feed is cached and
 * again when the cache is read back - a corrupt or hand-edited cache file must never be trusted
 * just because it exists. Mirrors the rules in the signature repo's own validator, minus the
 * corpus checks, which only make sense at authoring time.
 *
 * Also the ReDoS guard: field types are checked (a non-string pattern or id must not TypeError
 * later), the set size and pattern length are capped, and a regex with a quantified group that
 * itself contains a quantifier - the classic catastrophic-backtracking shape - is rejected.
 * An empty set is invalid: a feed (or cache) with no signatures would silently switch detection off.
 */
class SignatureSetValidator
{
    private const ALLOWED_SEVERITIES = ['critical', 'warning'];
    private const ALLOWED_PATTERN_TYPES = ['literal', 'regex'];
    private const MAX_SIGNATURES = 500;
    private const MAX_PATTERN_LENGTH = 2000;
    private const MAX_ID_LENGTH = 128;

    /**
     * A group containing a quantifier that is itself quantified, e.g. (a+)+ or (.*)*.
     */
    private const NESTED_QUANTIFIER = '/\\((?:[^()\\\\]|\\\\.)*[+*](?:[^()\\\\]|\\\\.)*\\)\\s*(?:[+*]|\\{\\d*,\\d*\\})/';

    private const REQUIRED_FIELDS = ['id', 'name', 'severity', 'target', 'pattern_type', 'pattern'];

    /**
     * @param array<string, mixed> $decoded
     */
    public function isValid(array $decoded): bool
    {
        if (!isset($decoded['signatures']) || !is_array($decoded['signatures'])) {
            return false;
        }

        if ($decoded['signatures'] === [] || count($decoded['signatures']) > self::MAX_SIGNATURES) {
            return false;
        }

        $seenIds = [];
        foreach ($decoded['signatures'] as $signature) {
            if (!is_array($signature) || !$this->isValidSignature($signature)) {
                return false;
            }
            if (isset($seenIds[$signature['id']])) {
                return false;
            }
            $seenIds[$signature['id']] = true;
        }

        return true;
    }

    /**
     * @param array<string, mixed> $signature
     */
    private function isValidSignature(array $signature): bool
    {
        foreach (self::REQUIRED_FIELDS as $field) {
            if (!isset($signature[$field]) || $signature[$field] === '') {
                return false;
            }
        }

        if (!is_string($signature['id']) || strlen($signature['id']) > self::MAX_ID_LENGTH
            || !is_string($signature['name']) || !is_string($signature['pattern'])
            || strlen($signature['pattern']) > self::MAX_PATTERN_LENGTH
            || !is_string($signature['severity']) || !is_string($signature['pattern_type'])
        ) {
            return false;
        }

        if (!in_array($signature['severity'], self::ALLOWED_SEVERITIES, true)) {
            return false;
        }
        if (!in_array($signature['pattern_type'], self::ALLOWED_PATTERN_TYPES, true)) {
            return false;
        }
        if (!is_array($signature['target']) || $signature['target'] === []) {
            return false;
        }
        foreach ($signature['target'] as $target) {
            if (!is_string($target)) {
                return false;
            }
        }

        if ($signature['pattern_type'] === 'regex') {
            // A non-compiling regex is a broken signature, not a fatal error - reject it here so
            // it never reaches ContentSignatureScanner.
            if (preg_match(self::NESTED_QUANTIFIER, $signature['pattern']) === 1) {
                return false;
            }

            // phpcs:ignore Generic.PHP.NoSilencedErrors.Discouraged
            return @preg_match($signature['pattern'], '') !== false;
        }

        return true;
    }
}
