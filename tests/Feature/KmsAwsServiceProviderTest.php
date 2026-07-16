<?php

declare(strict_types=1);

use Aws\Exception\UnresolvedApiException;
use Aws\Kms\KmsClient;
use Chronicle\KmsAws\Tests\TestCase;

uses(TestCase::class);

it('registers KmsClient as a singleton', function () {
    $first = app(KmsClient::class);
    $second = app(KmsClient::class);

    expect($first)->toBeInstanceOf(KmsClient::class)
        ->and($first)->toBe($second);
});

it('merges the package config with defaults for every key', function () {
    expect(config('chronicle-kms.region'))->toBe('us-east-1')
        ->and(config('chronicle-kms.version'))->toBe('latest')
        ->and(config('chronicle-kms.endpoint'))->toBeNull();
});

it('builds the KmsClient with the default region', function () {
    expect(app(KmsClient::class)->getRegion())->toBe('us-east-1');
});

it('builds the KmsClient with the configured region', function () {
    config()->set('chronicle-kms.region', 'eu-west-1');

    expect(app(KmsClient::class)->getRegion())->toBe('eu-west-1');
});

it('uses the SDK-derived endpoint when none is configured', function () {
    // No 'endpoint' key is passed to the client, so the SDK derives it from the
    // region - byte-for-byte the pre-config default.
    expect((string) app(KmsClient::class)->getEndpoint())
        ->toBe('https://kms.us-east-1.amazonaws.com');
});

it('builds the KmsClient with a configured custom endpoint', function () {
    config()->set('chronicle-kms.endpoint', 'http://localhost:4566');

    expect((string) app(KmsClient::class)->getEndpoint())
        ->toBe('http://localhost:4566');
});

it('ignores an empty-string endpoint and falls back to the SDK default', function () {
    config()->set('chronicle-kms.endpoint', '');

    expect((string) app(KmsClient::class)->getEndpoint())
        ->toBe('https://kms.us-east-1.amazonaws.com');
});

it('passes the configured version through to the client', function () {
    // A bogus version is rejected at construction - proof the config value
    // reaches the client rather than a hard-coded 'latest'.
    config()->set('chronicle-kms.version', '9999-99-99');

    expect(fn () => app(KmsClient::class))
        ->toThrow(UnresolvedApiException::class);
});

it('lets an app-level re-bind of KmsClient win over this provider', function () {
    // The documented escape hatch: re-binding after this provider registered
    // (the normal AppServiceProvider case) replaces the singleton entirely.
    $sentinel = new KmsClient([
        'region' => 'ap-southeast-2',
        'version' => 'latest',
        'credentials' => ['key' => 'sentinel', 'secret' => 'sentinel'],
    ]);

    app()->instance(KmsClient::class, $sentinel);

    expect(app(KmsClient::class))->toBe($sentinel);
});
