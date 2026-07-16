<?php

declare(strict_types=1);

use Aws\CommandInterface;
use Aws\Exception\AwsException;
use Aws\Kms\KmsClient;
use Aws\MockHandler;
use Aws\Result;
use Chronicle\KmsAws\KmsKeyEncryptionProvider;

function makeMockKmsClientForKek(array $responses): KmsClient
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
 * A KmsClient whose next operation fails with a realistic AwsException bound to the
 * real command - the command still carries the request params (for Encrypt, the
 * plaintext DEK), exactly as the live SDK would surface them.
 */
function kmsClientRaisingAwsExceptionForKek(string $awsErrorCode = 'AccessDeniedException'): KmsClient
{
    return makeMockKmsClientForKek([
        fn (CommandInterface $cmd): AwsException => new AwsException(
            'KMS operation failed',
            $cmd,
            ['code' => $awsErrorCode],
        ),
    ]);
}

it('kekId() returns the configured id', function () {
    $kms = makeMockKmsClientForKek([]);
    $provider = new KmsKeyEncryptionProvider(
        config: ['key' => 'arn:aws:kms:us-east-1:123:key/abc', 'id' => 'kms-prod'],
        client: $kms,
    );

    expect($provider->kekId())->toBe('kms-prod');
});

it('wrap() sends the DEK to KMS Encrypt and returns base64 of the CiphertextBlob', function () {
    $dek = random_bytes(32);
    $blob = 'CIPHERTEXT-BLOB-BYTES';

    $kms = makeMockKmsClientForKek([
        new Result(['CiphertextBlob' => $blob]),
    ]);

    $provider = new KmsKeyEncryptionProvider(
        config: ['key' => 'arn:aws:kms:us-east-1:123:key/abc', 'id' => 'kms-prod'],
        client: $kms,
    );

    expect($provider->wrap($dek))->toBe(base64_encode($blob));
});

it('unwrap() sends the blob to KMS Decrypt and returns the Plaintext DEK', function () {
    $dek = random_bytes(32);

    $kms = makeMockKmsClientForKek([
        new Result(['Plaintext' => $dek]),
    ]);

    $provider = new KmsKeyEncryptionProvider(
        config: ['key' => 'arn:aws:kms:us-east-1:123:key/abc', 'id' => 'kms-prod'],
        client: $kms,
    );

    expect($provider->unwrap(base64_encode('CIPHERTEXT-BLOB-BYTES')))->toBe($dek);
});

it('wrap()->unwrap() round-trips the DEK via mock KMS', function () {
    $dek = random_bytes(32);
    $blob = 'ROUND-TRIP-BLOB';

    $kms = makeMockKmsClientForKek([
        new Result(['CiphertextBlob' => $blob]),  // encrypt
        new Result(['Plaintext' => $dek]),        // decrypt
    ]);

    $provider = new KmsKeyEncryptionProvider(
        config: ['key' => 'arn:aws:kms:us-east-1:123:key/abc', 'id' => 'kms-prod'],
        client: $kms,
    );

    $wrapped = $provider->wrap($dek);

    expect($provider->unwrap($wrapped))->toBe($dek);
});

it('kekId() defaults to the KMS key when id is not configured', function () {
    $kms = makeMockKmsClientForKek([]);
    $provider = new KmsKeyEncryptionProvider(
        config: ['key' => 'arn:aws:kms:us-east-1:123:key/abc'],
        client: $kms,
    );

    expect($provider->kekId())->toBe('arn:aws:kms:us-east-1:123:key/abc');
});

it('kekId() falls back to the KMS key when id is an empty string', function () {
    $kms = makeMockKmsClientForKek([]);
    $provider = new KmsKeyEncryptionProvider(
        config: ['key' => 'arn:aws:kms:us-east-1:123:key/abc', 'id' => ''],
        client: $kms,
    );

    expect($provider->kekId())->toBe('arn:aws:kms:us-east-1:123:key/abc');
});

it('wrap() throws when KMS Encrypt returns no CiphertextBlob', function () {
    $kms = makeMockKmsClientForKek([
        new Result([]), // Encrypt result without a 'CiphertextBlob' key
    ]);

    $provider = new KmsKeyEncryptionProvider(
        config: ['key' => 'arn:aws:kms:us-east-1:123:key/abc', 'id' => 'kms-prod'],
        client: $kms,
    );

    $provider->wrap(random_bytes(32));
})->throws(RuntimeException::class, 'CiphertextBlob');

it('unwrap() throws when KMS Decrypt returns no Plaintext', function () {
    $kms = makeMockKmsClientForKek([
        new Result([]), // Decrypt result without a 'Plaintext' key
    ]);

    $provider = new KmsKeyEncryptionProvider(
        config: ['key' => 'arn:aws:kms:us-east-1:123:key/abc', 'id' => 'kms-prod'],
        client: $kms,
    );

    $provider->unwrap(base64_encode('CIPHERTEXT-BLOB-BYTES'));
})->throws(RuntimeException::class, 'Plaintext');

it('throws when the KMS key is an empty string', function () {
    $kms = makeMockKmsClientForKek([]);
    new KmsKeyEncryptionProvider(config: ['key' => '', 'id' => 'kms-prod'], client: $kms);
})->throws(InvalidArgumentException::class, 'key');

it('throws when the KMS key is missing from config', function () {
    $kms = makeMockKmsClientForKek([]);
    new KmsKeyEncryptionProvider(config: ['id' => 'kms-prod'], client: $kms);
})->throws(InvalidArgumentException::class, 'key');

it('throws when unwrap() receives non-base64 input', function () {
    $kms = makeMockKmsClientForKek([]);
    $provider = new KmsKeyEncryptionProvider(
        config: ['key' => 'arn:aws:kms:us-east-1:123:key/abc', 'id' => 'kms-prod'],
        client: $kms,
    );

    $provider->unwrap('!!!not-base64!!!');
})->throws(InvalidArgumentException::class);

// ---------------------------------------------------------------------------
// Item 2 - a KMS failure must never carry the plaintext DEK into an exception
// ---------------------------------------------------------------------------

it('wrap() sanitizes KMS failures and never leaks the plaintext DEK', function () {
    // A recognisable stand-in for the 32-byte DEK, so we can grep the exception for it.
    $dek = 'SENSITIVE-DEK-MARKER-0123456789abcdef';

    $kms = kmsClientRaisingAwsExceptionForKek();

    $provider = new KmsKeyEncryptionProvider(
        config: ['key' => 'arn:aws:kms:us-east-1:123:key/abc', 'id' => 'kms-prod'],
        client: $kms,
    );

    try {
        $provider->wrap($dek);
        $this->fail('wrap() should have thrown on KMS failure.');
    } catch (Throwable $e) {
        // Sanitized: a plain RuntimeException, not the raw AwsException, and not
        // chained as a previous (getPrevious() on the AwsException still reaches
        // the plaintext DEK via getCommand()).
        expect($e)->toBeInstanceOf(RuntimeException::class)
            ->and($e)->not->toBeInstanceOf(AwsException::class)
            ->and($e->getPrevious())->toBeNull()
            // The DEK must appear in none of the exception's string forms.
            ->and($e->getMessage())->not->toContain($dek)
            ->and($e->getTraceAsString())->not->toContain($dek)
            ->and((string) $e)->not->toContain($dek)
            // Safe metadata is preserved for debuggability.
            ->and($e->getMessage())->toContain('Encrypt')
            ->and($e->getMessage())->toContain('AccessDeniedException');
    }
});

it('unwrap() sanitizes KMS failures without propagating raw AWS context', function () {
    $wrapped = base64_encode('CIPHERTEXT-BLOB-BYTES');

    $kms = kmsClientRaisingAwsExceptionForKek('KMSInvalidStateException');

    $provider = new KmsKeyEncryptionProvider(
        config: ['key' => 'arn:aws:kms:us-east-1:123:key/abc', 'id' => 'kms-prod'],
        client: $kms,
    );

    try {
        $provider->unwrap($wrapped);
        $this->fail('unwrap() should have thrown on KMS failure.');
    } catch (Throwable $e) {
        expect($e)->toBeInstanceOf(RuntimeException::class)
            ->and($e)->not->toBeInstanceOf(AwsException::class)
            ->and($e->getPrevious())->toBeNull()
            ->and($e->getMessage())->toContain('Decrypt')
            ->and($e->getMessage())->toContain('KMSInvalidStateException');
    }
});

// ---------------------------------------------------------------------------
// Item 4 - a corrupted wrapped DEK is rejected, never silently unwrapped
// ---------------------------------------------------------------------------

it('unwrap() rejects a corrupted wrapped DEK instead of passing garbage downstream', function () {
    $dek = random_bytes(32);
    $blob = 'ROUND-TRIP-BLOB';

    $kms = makeMockKmsClientForKek([
        new Result(['CiphertextBlob' => $blob]), // encrypt
    ]);

    $provider = new KmsKeyEncryptionProvider(
        config: ['key' => 'arn:aws:kms:us-east-1:123:key/abc', 'id' => 'kms-prod'],
        client: $kms,
    );

    $wrapped = $provider->wrap($dek);

    // Corrupt one character with a byte outside the base64 alphabet.
    $corrupted = '@'.substr($wrapped, 1);

    // No Decrypt response is queued: a valid corrupted-but-decodable value would
    // reach KMS, but this one must be rejected by the base64 guard first.
    expect(fn () => $provider->unwrap($corrupted))
        ->toThrow(InvalidArgumentException::class);
});
