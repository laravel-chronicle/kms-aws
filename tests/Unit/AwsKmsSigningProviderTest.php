<?php

declare(strict_types=1);

use Aws\CommandInterface;
use Aws\Exception\AwsException;
use Aws\Kms\KmsClient;
use Aws\MockHandler;
use Aws\Result;
use Chronicle\KmsAws\AwsKmsSigningProvider;

// ---------------------------------------------------------------------------
// Test helpers - fixed P-256 keypair (same vectors as core plan)
// ---------------------------------------------------------------------------

function kmsTestPublicPem(): string
{
    return "-----BEGIN PUBLIC KEY-----\n".
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEo3aNjcgA2+dbcfDdxu502FZ6Op7n\n".
        "4wVHCauIGLnNswY29w0BRjvKYdn5SWMQEDLhcOvTQGw52g5Y9TEI1E78lg==\n".
        "-----END PUBLIC KEY-----\n";
}

function kmsTestPrivatePem(): string
{
    return "-----BEGIN PRIVATE KEY-----\n".
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgW+bV8zg4mNoXrTXz\n".
        "vy3jy0tYCc/+V1Zm2hiVlhYQxwShRANCAASjdo2NyADb51tx8N3G7nTYVno6nufj\n".
        "BUcJq4gYuc2zBjb3DQFGO8ph2flJYxAQMuFw69NAbDnaDlj1MQjUTvyW\n".
        "-----END PRIVATE KEY-----\n";
}

// A *second*, distinct P-256 keypair (fixed vector) for the wrong-key forgery test.
function kmsTestPublicPem2(): string
{
    return "-----BEGIN PUBLIC KEY-----\n".
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6/FcJwi0QMX5HzC2tlZ6YMmP3eNi\n".
        "QT2sJbppyH1F2q9UGzdInnkM+aig2aSteUcA6brypw/VIdCr5kdd96L3UA==\n".
        "-----END PUBLIC KEY-----\n";
}

function kmsTestPrivatePem2(): string
{
    return "-----BEGIN PRIVATE KEY-----\n".
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgv9vWayNby/fkEwdF\n".
        "tFNX//cSw3tq4FM/RtkvVHbABaqhRANCAATr8VwnCLRAxfkfMLa2VnpgyY/d42JB\n".
        "PawlumnIfUXar1QbN0ieeQz5qKDZpK15RwDpuvKnD9Uh0KvmR133ovdQ\n".
        "-----END PRIVATE KEY-----\n";
}

/**
 * Create a KmsClient backed by a MockHandler that returns $responses in order.
 * Each entry in $responses must be an Aws\Result or an exception.
 */
function makeMockKmsClient(array $responses): KmsClient
{
    $mock = new MockHandler($responses);

    return new KmsClient([
        'region' => 'us-east-1',
        'version' => 'latest',
        'credentials' => ['key' => 'AKIAIOSFODNN7EXAMPLE', 'secret' => 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'],
        'handler' => $mock,
    ]);
}

/**
 * A KmsClient whose next operation fails with a realistic AwsException bound to
 * the real command, exactly as the live SDK would surface a KMS error.
 */
function kmsClientRaisingAwsException(string $awsErrorCode = 'AccessDeniedException'): KmsClient
{
    return makeMockKmsClient([
        fn (CommandInterface $cmd): AwsException => new AwsException(
            'KMS operation failed',
            $cmd,
            ['code' => $awsErrorCode],
        ),
    ]);
}

// ---------------------------------------------------------------------------

it('algorithm() returns ecdsa-p256', function () {
    $kms = makeMockKmsClient([]);
    $provider = new AwsKmsSigningProvider(
        config: [
            'key_arn' => 'arn:aws:kms:us-east-1:123:key/test',
            'public_key' => kmsTestPublicPem(),
            'key_id' => 'kms-key',
        ],
        client: $kms,
    );

    expect($provider->algorithm())->toBe('ecdsa-p256');
});

it('keyId() returns the configured key id', function () {
    $kms = makeMockKmsClient([]);
    $provider = new AwsKmsSigningProvider(
        config: [
            'key_arn' => 'arn:aws:kms:us-east-1:123:key/test',
            'public_key' => kmsTestPublicPem(),
            'key_id' => 'my-kms-key',
        ],
        client: $kms,
    );

    expect($provider->keyId())->toBe('my-kms-key');
});

it('sign() calls KMS with DIGEST mode and returns base64 of the KMS signature', function () {
    $payload = 'chronicle-kms-test-payload';

    // Produce a valid ECDSA P-256 DER signature using the test private key.
    // The mock KMS "returns" this value - proving sign() passes the result through.
    openssl_sign($payload, $derSig, kmsTestPrivatePem(), OPENSSL_ALGO_SHA256);

    $kms = makeMockKmsClient([
        new Result(['Signature' => $derSig]),
    ]);

    $provider = new AwsKmsSigningProvider(
        config: [
            'key_arn' => 'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
            'public_key' => kmsTestPublicPem(),
            'key_id' => 'kms-key',
        ],
        client: $kms,
    );

    $sig = $provider->sign($payload);

    expect($sig)->toBe(base64_encode($derSig));
});

it('verify() returns true for a valid signature - local, no network call', function () {
    $payload = 'chronicle-kms-test-payload';

    // Sign locally to get a valid DER signature
    openssl_sign($payload, $derSig, kmsTestPrivatePem(), OPENSSL_ALGO_SHA256);
    $sigB64 = base64_encode($derSig);

    // MockHandler has no entries - verify() must NOT call KMS
    $kms = makeMockKmsClient([]);

    $provider = new AwsKmsSigningProvider(
        config: [
            'key_arn' => 'arn:aws:kms:us-east-1:123:key/test',
            'public_key' => kmsTestPublicPem(),
            'key_id' => 'kms-key',
        ],
        client: $kms,
    );

    expect($provider->verify($payload, $sigB64))->toBeTrue();
});

it('verify() returns false for a tampered payload - local, no network call', function () {
    $payload = 'chronicle-kms-test-payload';
    openssl_sign($payload, $derSig, kmsTestPrivatePem(), OPENSSL_ALGO_SHA256);
    $sigB64 = base64_encode($derSig);

    $kms = makeMockKmsClient([]);
    $provider = new AwsKmsSigningProvider(
        config: [
            'key_arn' => 'arn:aws:kms:us-east-1:123:key/test',
            'public_key' => kmsTestPublicPem(),
            'key_id' => 'kms-key',
        ],
        client: $kms,
    );

    expect($provider->verify('tampered-payload', $sigB64))->toBeFalse();
});

it('sign() then verify() round-trip via mock KMS', function () {
    $payload = 'chronicle-round-trip';

    // Produce the signature that mock KMS will "return"
    openssl_sign($payload, $derSig, kmsTestPrivatePem(), OPENSSL_ALGO_SHA256);

    $kms = makeMockKmsClient([
        new Result(['Signature' => $derSig]),
    ]);

    $provider = new AwsKmsSigningProvider(
        config: [
            'key_arn' => 'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
            'public_key' => kmsTestPublicPem(),
            'key_id' => 'kms-key',
        ],
        client: $kms,
    );

    $sig = $provider->sign($payload);

    expect($provider->verify($payload, $sig))->toBeTrue();
});

it('keyId() defaults to "none" when key_id is not configured', function () {
    $kms = makeMockKmsClient([]);
    $provider = new AwsKmsSigningProvider(
        config: [
            'key_arn' => 'arn:aws:kms:us-east-1:123:key/test',
            'public_key' => kmsTestPublicPem(),
        ],
        client: $kms,
    );

    expect($provider->keyId())->toBe('none');
});

it('sign() throws when KMS returns no Signature value', function () {
    $kms = makeMockKmsClient([
        new Result([]), // KMS Sign result without a 'Signature' key
    ]);

    $provider = new AwsKmsSigningProvider(
        config: [
            'key_arn' => 'arn:aws:kms:us-east-1:123:key/test',
            'public_key' => kmsTestPublicPem(),
            'key_id' => 'kms-key',
        ],
        client: $kms,
    );

    $provider->sign('payload');
})->throws(RuntimeException::class, 'Signature');

it('throws when key_arn is an empty string', function () {
    $kms = makeMockKmsClient([]);
    new AwsKmsSigningProvider(
        config: ['key_arn' => '', 'public_key' => kmsTestPublicPem(), 'key_id' => 'test'],
        client: $kms,
    );
})->throws(InvalidArgumentException::class, 'key_arn');

it('throws when public_key is an empty string', function () {
    $kms = makeMockKmsClient([]);
    new AwsKmsSigningProvider(
        config: ['key_arn' => 'arn:aws:kms:us-east-1:123:key/test', 'public_key' => '', 'key_id' => 'test'],
        client: $kms,
    );
})->throws(InvalidArgumentException::class, 'public_key');

it('throws when key_arn is missing from config', function () {
    $kms = makeMockKmsClient([]);
    new AwsKmsSigningProvider(
        config: ['public_key' => kmsTestPublicPem(), 'key_id' => 'test'],
        client: $kms,
    );
})->throws(InvalidArgumentException::class, 'key_arn');

it('throws when public_key is missing from config', function () {
    $kms = makeMockKmsClient([]);
    new AwsKmsSigningProvider(
        config: ['key_arn' => 'arn:aws:kms:us-east-1:123:key/test', 'key_id' => 'test'],
        client: $kms,
    );
})->throws(InvalidArgumentException::class, 'public_key');

// ---------------------------------------------------------------------------
// Item 2 - a KMS Sign failure must not carry the payload or raw AWS context
// ---------------------------------------------------------------------------

it('sign() sanitizes KMS failures without leaking the payload or raw AWS context', function () {
    // Only SHA256(payload) is ever sent to KMS, so the payload cannot appear in
    // the command - but we still pin that it never surfaces in the exception.
    $payload = 'SENSITIVE-PAYLOAD-MARKER-0123456789';

    $kms = kmsClientRaisingAwsException('KMSInvalidStateException');

    $provider = new AwsKmsSigningProvider(
        config: [
            'key_arn' => 'arn:aws:kms:us-east-1:123:key/test',
            'public_key' => kmsTestPublicPem(),
            'key_id' => 'kms-key',
        ],
        client: $kms,
    );

    try {
        $provider->sign($payload);
        $this->fail('sign() should have thrown on KMS failure.');
    } catch (Throwable $e) {
        expect($e)->toBeInstanceOf(RuntimeException::class)
            ->and($e)->not->toBeInstanceOf(AwsException::class)
            ->and($e->getPrevious())->toBeNull()
            ->and($e->getMessage())->not->toContain($payload)
            ->and($e->getTraceAsString())->not->toContain($payload)
            ->and((string) $e)->not->toContain($payload)
            ->and($e->getMessage())->toContain('Sign')
            ->and($e->getMessage())->toContain('KMSInvalidStateException');
    }
});

// ---------------------------------------------------------------------------
// Item 5 - verify() must reject a valid signature made by the wrong key
// ---------------------------------------------------------------------------

it('verify() returns false for a signature made by a different keypair', function () {
    $payload = 'chronicle-kms-test-payload';

    // A well-formed signature over the CORRECT payload, but signed with the
    // SECOND private key - the realistic forgery attempt.
    openssl_sign($payload, $forgedSig, kmsTestPrivatePem2(), OPENSSL_ALGO_SHA256);
    $forgedB64 = base64_encode($forgedSig);

    // Provider is configured with the ORIGINAL public key.
    $kms = makeMockKmsClient([]);
    $provider = new AwsKmsSigningProvider(
        config: [
            'key_arn' => 'arn:aws:kms:us-east-1:123:key/test',
            'public_key' => kmsTestPublicPem(),
            'key_id' => 'kms-key',
        ],
        client: $kms,
    );

    expect($provider->verify($payload, $forgedB64))->toBeFalse();
});
