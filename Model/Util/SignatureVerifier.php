<?php
/**
 * Copyright © StackNuts. All rights reserved.
 * See LICENSE for license details.
 */

declare(strict_types=1);

namespace StackNuts\StackGaugeSecurity\Model\Util;

/**
 * Verifies a signature set's detached Ed25519 signature (signatures.json.sig) against the public
 * keys pinned in this module. Used both when a feed is downloaded (SignatureFeedFetcher) and every
 * time the cached copy is read back (SignatureStore), so a cache file that was written or edited
 * by anything other than a successful, verified fetch is never trusted.
 */
class SignatureVerifier
{
    /**
     * Base64 Ed25519 public keys allowed to sign the feed, by key id - the same ids as the
     * signatures repo's signing-keys/<id>.pub. To rotate: add the new key here alongside the old
     * one, release, start signing with the new key, then drop the old one in a later release.
     */
    public const TRUSTED_KEYS = [
        'stackgauge-2026-10' => 'FK/VR4hQNnPLg0E98ArlZW2MK2Vs+rClGNKpBk7E8mI=',
    ];

    /**
     * @param array<string, string> $trustedKeys key id => base64 public key; TRUSTED_KEYS unless a
     *     test needs to sign with its own throwaway key
     */
    public function __construct(private readonly array $trustedKeys = self::TRUSTED_KEYS)
    {
    }

    /**
     * Whether $signatureFile ({"algorithm": "ed25519", "key_id": ..., "signature": <base64>})
     * is a valid detached signature over the exact bytes of $body by one of the trusted keys.
     *
     * @param string $body
     * @param string $signatureFile
     */
    public function isSignedByTrustedKey(string $body, string $signatureFile): bool
    {
        $envelope = json_decode($signatureFile, true);
        if (!is_array($envelope) || ($envelope['algorithm'] ?? null) !== 'ed25519') {
            return false;
        }

        $keyId = $envelope['key_id'] ?? null;
        if (!is_string($keyId)) {
            return false;
        }

        $publicKey = base64_decode($this->trustedKeys[$keyId] ?? '', true);
        $signature = base64_decode((string)($envelope['signature'] ?? ''), true);

        if ($publicKey === false || strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            || $signature === false || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES
        ) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, $body, $publicKey);
    }
}
