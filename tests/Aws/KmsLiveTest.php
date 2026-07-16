<?php

declare(strict_types=1);

use Aws\Kms\KmsClient;
use Chronicle\KmsAws\AwsKmsSigningProvider;
use Chronicle\KmsAws\KmsKeyEncryptionProvider;

// ---------------------------------------------------------------------------
// Real-AWS tier - opt-in, tiny backstop that confirms our mental model of the
// live KMS contract (see CONTRIBUTING.md "real-AWS tier"). It is NOT a re-run of
// the mocked suite against live infrastructure.
//
// SAFETY: these tests use pre-existing, operator-supplied test keys. They never
// create, disable, or ScheduleKeyDeletion on any key - key lifecycle is out of
// band. Plaintext DEKs are never logged or persisted.
//
// This whole file is tagged `aws` and lives outside the Unit/Feature testsuites,
// so `composer test` never discovers it. Run it with `composer test:aws`.
// ---------------------------------------------------------------------------

/**
 * Read an env var from the process environment (getenv falls back to the CI /
 * shell environment where the AWS SDK also looks).
 */
function kmsAwsEnv(string $key): ?string
{
    $value = getenv($key);

    if ($value === false || $value === '') {
        return null;
    }

    return $value;
}

/**
 * Resolve the signing key's public PEM from KMS_TEST_SIGNING_PUBLIC_KEY, which
 * may be either an inline PEM or a path to a .pem file.
 */
function kmsAwsSigningPublicPem(string $raw): string
{
    if (str_contains($raw, 'BEGIN PUBLIC KEY')) {
        return $raw;
    }

    if (! is_file($raw)) {
        throw new RuntimeException(
            "KMS_TEST_SIGNING_PUBLIC_KEY is neither an inline PEM nor a readable file path: {$raw}"
        );
    }

    $pem = file_get_contents($raw);

    if ($pem === false || ! str_contains($pem, 'BEGIN PUBLIC KEY')) {
        throw new RuntimeException("KMS_TEST_SIGNING_PUBLIC_KEY file does not contain a PEM public key: {$raw}");
    }

    return $pem;
}

/**
 * The tier's safety bootstrap. Runs before every test in this file:
 *
 *  - opt-in flag absent          -> skip cleanly with an explanatory message
 *  - flag set but keys missing   -> fail loudly (a half-configured run is a bug)
 *  - flag set and keys present   -> hand back a live KmsClient + resolved config
 *
 * @return array{
 *     client: KmsClient,
 *     region: string,
 *     signingKeyArn: string,
 *     signingPublicPem: string,
 *     encryptionKeyArn: string,
 *     deniedKeyArn: string
 * }
 */
function kmsAwsTestContext(): array
{
    if (kmsAwsEnv('KMS_AWS_TESTS') !== '1') {
        test()->markTestSkipped(
            'AWS live tier skipped: set KMS_AWS_TESTS=1 and the KMS_TEST_* key env vars to run (see CONTRIBUTING.md).'
        );
    }

    $region = kmsAwsEnv('AWS_DEFAULT_REGION');
    $signingKeyArn = kmsAwsEnv('KMS_TEST_SIGNING_KEY_ARN');
    $signingPublicKey = kmsAwsEnv('KMS_TEST_SIGNING_PUBLIC_KEY');
    $encryptionKeyArn = kmsAwsEnv('KMS_TEST_ENCRYPTION_KEY_ARN');

    $missing = [];

    if ($region === null) {
        $missing[] = 'AWS_DEFAULT_REGION';
    }
    if ($signingKeyArn === null) {
        $missing[] = 'KMS_TEST_SIGNING_KEY_ARN';
    }
    if ($signingPublicKey === null) {
        $missing[] = 'KMS_TEST_SIGNING_PUBLIC_KEY';
    }
    if ($encryptionKeyArn === null) {
        $missing[] = 'KMS_TEST_ENCRYPTION_KEY_ARN';
    }

    if ($missing !== []) {
        // Opt-in flag is set but the run is half-configured: be loud, not silent.
        throw new RuntimeException(
            'KMS_AWS_TESTS=1 but required env vars are missing: '.implode(', ', $missing).'.'
        );
    }

    /** @var string $region */
    /** @var string $signingKeyArn */
    /** @var string $signingPublicKey */
    /** @var string $encryptionKeyArn */

    // A key the principal cannot use. Defaults to a well-formed ARN pointing at a
    // random (non-existent) key id in the same account/region as the signing key,
    // which KMS rejects with NotFoundException. An operator may instead supply a
    // genuinely disabled/unauthorized key via KMS_TEST_DENIED_KEY_ARN.
    $deniedKeyArn = kmsAwsEnv('KMS_TEST_DENIED_KEY_ARN')
        ?? preg_replace(
            '#key/[^/]+$#',
            'key/'.kmsAwsRandomUuid(),
            $signingKeyArn
        );

    // If the signing ARN wasn't in the key/<id> form, fall back to a synthetic ARN.
    if (! is_string($deniedKeyArn) || ! str_contains($deniedKeyArn, 'key/')) {
        $deniedKeyArn = "arn:aws:kms:{$region}:000000000000:key/".kmsAwsRandomUuid();
    }

    $client = new KmsClient([
        'region' => $region,
        'version' => 'latest',
        // Credentials flow through the standard AWS chain (env / IAM role).
    ]);

    return [
        'client' => $client,
        'region' => $region,
        'signingKeyArn' => $signingKeyArn,
        'signingPublicPem' => kmsAwsSigningPublicPem($signingPublicKey),
        'encryptionKeyArn' => $encryptionKeyArn,
        'deniedKeyArn' => $deniedKeyArn,
    ];
}

/**
 * A random v4 UUID for a guaranteed-non-existent KMS key id.
 */
function kmsAwsRandomUuid(): string
{
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0F) | 0x40);
    $bytes[8] = chr((ord($bytes[8]) & 0x3F) | 0x80);

    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
}

// ---------------------------------------------------------------------------

beforeEach(function () {
    $this->kms = kmsAwsTestContext();
});

it('produces a KMS signature that verifies locally against the cached public key', function () {
    // THE test that matters: a signature actually produced by live KMS must verify
    // against the PEM we cache. No mock can prove our verification is compatible
    // with real KMS ECDSA output.
    $provider = new AwsKmsSigningProvider(
        config: [
            'key_arn' => $this->kms['signingKeyArn'],
            'public_key' => $this->kms['signingPublicPem'],
            'key_id' => 'kms-live',
        ],
        client: $this->kms['client'],
    );

    $payload = 'chronicle-live-'.bin2hex(random_bytes(8));

    $signature = $provider->sign($payload);

    expect($provider->verify($payload, $signature))->toBeTrue()
        ->and($provider->verify($payload.'-tampered', $signature))->toBeFalse();
})->group('aws');

it('round-trips a DEK through real KMS Encrypt/Decrypt', function () {
    $provider = new KmsKeyEncryptionProvider(
        config: ['key' => $this->kms['encryptionKeyArn']],
        client: $this->kms['client'],
    );

    // A known, random 32-byte DEK. Never logged or persisted.
    $dek = random_bytes(32);

    $wrapped = $provider->wrap($dek);
    $unwrapped = $provider->unwrap($wrapped);

    expect($unwrapped)->toBe($dek)
        ->and($wrapped)->not->toBe(base64_encode($dek)); // actually encrypted, not passthrough
})->group('aws');

it('rejects a genuine KMS signature when verified against a different public key', function () {
    // Sign with real KMS, then verify against an unrelated P-256 public key. Proves
    // verification is bound to the configured key even against authentic KMS output.
    $signer = new AwsKmsSigningProvider(
        config: [
            'key_arn' => $this->kms['signingKeyArn'],
            'public_key' => $this->kms['signingPublicPem'],
        ],
        client: $this->kms['client'],
    );

    $payload = 'chronicle-live-wrongkey-'.bin2hex(random_bytes(8));
    $signature = $signer->sign($payload);

    // A freshly generated, unrelated P-256 keypair - self-contained, no fixtures.
    $other = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_EC,
        'curve_name' => 'prime256v1',
    ]);
    expect($other)->not->toBeFalse();

    $details = openssl_pkey_get_details($other);
    expect($details)->toBeArray();

    $wrongVerifier = new AwsKmsSigningProvider(
        config: [
            'key_arn' => $this->kms['signingKeyArn'],
            'public_key' => $details['key'],
        ],
        client: $this->kms['client'],
    );

    expect($wrongVerifier->verify($payload, $signature))->toBeFalse();
})->group('aws');

it('fails loudly when the KMS key cannot be used', function () {
    // Per session decision: point at a well-formed ARN with a non-existent key id
    // (or an operator-supplied KMS_TEST_DENIED_KEY_ARN). The operation must throw a
    // clear error - never return empty or partial output a caller could trust.
    $provider = new KmsKeyEncryptionProvider(
        config: ['key' => $this->kms['deniedKeyArn']],
        client: $this->kms['client'],
    );

    expect(fn () => $provider->wrap(random_bytes(32)))
        ->toThrow(RuntimeException::class);
})->group('aws');

it('rejects a tampered ciphertext instead of returning usable output', function () {
    $provider = new KmsKeyEncryptionProvider(
        config: ['key' => $this->kms['encryptionKeyArn']],
        client: $this->kms['client'],
    );

    $wrapped = $provider->wrap(random_bytes(32));

    // Flip a byte deep inside the real CiphertextBlob and re-encode.
    $blob = base64_decode($wrapped, true);
    expect($blob)->toBeString();

    $index = intdiv(strlen($blob), 2);
    $blob[$index] = $blob[$index] === "\x00" ? "\x01" : "\x00";
    $tampered = base64_encode($blob);

    expect(fn () => $provider->unwrap($tampered))
        ->toThrow(RuntimeException::class);
})->group('aws');
