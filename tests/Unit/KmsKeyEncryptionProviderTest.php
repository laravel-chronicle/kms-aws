<?php

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
