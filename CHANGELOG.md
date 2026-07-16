# Changelog

All notable changes to `laravel-chronicle/kms-aws` are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [1.2.0] - 2026-07-17

### Added

- Opt-in **real-AWS test tier** (`composer test:aws`): a tiny (~5 test) backstop that runs the mocked suite's blind spot against live KMS - most importantly, that a signature produced by real KMS verifies against our cached PEM. It is grouped `aws`, lives outside the default testsuites so `composer test` never touches it, skips cleanly when unconfigured, and fails loudly if opted in (`KMS_AWS_TESTS=1`) but misconfigured. The tests use pre-existing, operator-managed keys and never create or schedule deletion of any key. Added `.env.example` documenting the required env vars and a `aws-tests.yml` workflow that runs the tier on push to `main` and nightly only (never on `pull_request`). LocalStack is intentionally not used - see `CONTRIBUTING.md`.
- Configurable KMS client `endpoint` (optional; for LocalStack / KMS FIPS endpoints) and `version` (defaults to `latest`) via `config/chronicle-kms.php`, read from `CHRONICLE_KMS_ENDPOINT` / `CHRONICLE_KMS_VERSION`. When `endpoint` is unset the client is built without it, so the default resolved client is byte-for-byte unchanged. The re-bind escape hatch remains for anything the config keys do not cover.
- `declare(strict_types=1)` across all source and config files.
- Package metadata in `composer.json`: `homepage`, `support`, and `funding` entries.
- Expanded the test suite to 100% coverage, including error paths, default branches, and a Feature test for `KmsAwsServiceProvider`.
- Tests covering the failure and safety edges of both providers: KMS "returned no usable field" throws, the base64 guard and a corruption round-trip in `unwrap()`, and rejection of a valid signature made by the wrong keypair in `verify()`.
- Security docblock on `KmsKeyEncryptionProvider::unwrap()` documenting that the returned plaintext DEK is live key material whose lifetime the caller owns (must not be logged, persisted, or serialized).
- `CHANGELOG.md` and `CONTRIBUTING.md`.

### Changed

- `KmsKeyEncryptionProvider` properties (`keyId`, `kekId`, `kms`) changed from `private` to `protected` to allow subclassing.

### Security

- KMS SDK failures in `wrap()`, `unwrap()`, and `sign()` are now caught and rethrown as a sanitized `RuntimeException` carrying only the operation name and AWS error code. The original `AwsException` is deliberately **not** chained, because its `getCommand()` still holds the request material (for `Encrypt`, the plaintext DEK) - this prevents key material from leaking into logs or crash reporters via the exception chain. `AwsException` extends `RuntimeException`, so callers catching `RuntimeException` are unaffected.

### Fixed

- Corrected the provider name in the `public_key` validation exception message (was "AwsKmsSingingProvider").
- Fixed "KSM" typos in the `AwsKmsSigningProvider` docblock.

---

## [1.1.0] - 2026-06-18

### Added

- `KmsKeyEncryptionProvider`: a KMS-backed KEK provider for Chronicle crypto-shredding. Wraps and unwraps per-subject DEKs through the AWS KMS Encrypt/Decrypt APIs so the key-encryption key never leaves the HSM. Resolved by `KeyEncryptionManager::providerFor()` with the `KmsClient` auto-injected. Requires the `kms:Encrypt` and `kms:Decrypt` IAM actions.
- README documentation for configuring the KEK provider.

---

## [1.0.0] - 2026-06-04

### Added

- `AwsKmsSigningProvider`: signs `SHA256(payload)` through the AWS KMS Sign API (DIGEST mode, `ECDSA_SHA_256`) and verifies locally via `LocalVerifyProvider` using a cached PEM public key, requiring no network call for verification. Requires the `kms:Sign` and `kms:DescribeKey` IAM actions.
- `KmsAwsServiceProvider`: registers a `KmsClient` singleton resolved from the configured region / AWS environment variables, and publishes the `chronicle-kms` config.
- README with installation, IAM policy, and configuration examples.

[Unreleased]: https://github.com/laravel-chronicle/kms-aws/compare/1.2.0...HEAD
[1.2.0]: https://github.com/laravel-chronicle/kms-aws/compare/1.1.0...1.2.0
[1.1.0]: https://github.com/laravel-chronicle/kms-aws/compare/1.0.0...1.1.0
[1.0.0]: https://github.com/laravel-chronicle/kms-aws/releases/tag/1.0.0
