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
 */
class ContentSignatureScanner
{
    private const PATTERN_TYPE_LITERAL = 'literal';
    private const PATTERN_TYPE_REGEX = 'regex';

    /**
     * Ids of regex signatures that errored (most often PCRE's backtrack limit on a large body)
     * during any scan() so far - see getErroredSignatureIds().
     *
     * @var array<string, true>
     */
    private array $erroredSignatureIds = [];

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
            self::PATTERN_TYPE_LITERAL => str_contains($body, $signature['pattern']),
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
