<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Util;

/**
 * One human-readable "what's active right now" line, shared between the admin config display
 * (FetchSignatures block, rendered at page load) and the "Fetch Latest Signatures Now" AJAX
 * response (FetchSignatures controller, rendered after a refresh) - so both always describe the
 * active set the same way.
 */
class SignatureStatusText
{
    public function build(?string $version, int $count, string $source): string
    {
        $sourceLabel = match ($source) {
            SignatureStore::SOURCE_FEED => 'fetched feed',
            SignatureStore::SOURCE_BUNDLED => 'bundled fallback',
            default => 'none',
        };

        return (string)__(
            'Currently using version %1 (%2 signatures, source: %3).',
            $version ?? 'unknown',
            $count,
            $sourceLabel
        );
    }
}
