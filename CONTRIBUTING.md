# Contributing to kms-aws

This package moves Chronicle's cryptographic key operations into [AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/overview.html), so that key material lives inside a KMS-managed HSM rather than on the application server. It provides two independent providers:

- **`KmsKeyEncryptionProvider`** - the KEK for crypto-shredding. It wraps and unwraps per-subject data-encryption keys (DEKs) through KMS `Encrypt`/`Decrypt`, so the key-encryption key never leaves KMS.
- **`AwsKmsSigningProvider`** - checkpoint and export signing. It sends an SHA-256 digest to KMS `Sign` (ECDSA P-256), and verifies locally against a cached PEM public key with no network call.

Everything in the [organization-wide contributing guide](https://github.com/laravel-chronicle/.github/blob/main/CONTRIBUTING.md) applies here. This page covers what's specific to this package.

## The guarantee this package protects

The private key material - the KEK behind crypto-shredding, and the signing key behind checkpoint integrity - must never leave KMS. That is the entire reason to use this package instead of the local providers. It places two hard rules on every contribution:

1. **Plaintext key material must never persist outside KMS' boundary.** The KEK and the signing private key exist only inside KMS by design. The only plaintext that legitimately crosses the boundary is a DEK returned by `Decrypt` during `unwrap()`, and that value must be used and discarded - never logged, never written to disk, never placed in an exception message, never returned in serialized output, never left where a log aggregator or stack trace could capture it. If your change causes any key or DEK plaintext to surface somewhere readable, that is a security bug, not a style nit.

2. **Shredding must stay real.** Crypto-shredding works only because a DEK becomes permanently unrecoverable once destroyed. Anything that caches, persists, or copies a decrypted DEK - even as a performance optimization to save a KMS round-trip - can leave a copy behind that defeats erasure. Do not add caching of decrypted key material without raising it in an issue first. The answer is almost always no.

If you find a way to make either fail, do **not** open a public issue - report it privately per [SECURITY.md](https://github.com/laravel-chronicle/.github/blob/main/SECURITY.md).

## Setup

```bash
git clone git@github.com:laravel-chronicle/kms-aws.git
cd kms-aws
composer install
composer test
```

`composer test` runs the full pipeline - Pint style check, PHPStan, then the Pest suite. It passes with **no AWS account, no credentials, and no configuration**: every test runs against a mocked KMS client, so `composer install && composer test` is green out of the box. A contributor never needs AWS access to work on this package.

Individual steps, if you want them:

```bash
composer test:lint    # Pint, dry run
composer test:types   # PHPStan level 10
composer test:unit    # Pest (mocked, zero-config)
composer test:aws     # Pest, real-AWS tier only (opt-in - see below)
composer lint         # Pint, actually apply fixes
```

## How the tests work

The suite mocks KMS with the AWS SDK's own `MockHandler`, constructing a real `KmsClient` whose responses are canned `Aws\Result` objects. See `makeMockKmsClientForKek()` in `tests/Unit/KmsKeyEncryptionProviderTest.php` and the equivalent in `tests/Unit/AwsKmsSigningProviderTest.php` for the pattern - mirror it rather than inventing a new mocking approach.

This means the mocked tests verify the provider's half of the contract: what it sends to KMS, how it interprets responses, and how it fails when KMS returns something unexpected. Because both providers treat KMS output as opaque bytes and do the interesting logic locally (base64 framing on the encryption side; local ECDSA verification on the signing side), the mocked tests cover the provider's own behavior well.

## The real-AWS tier

There is one thing a mock cannot prove: that our understanding of the **real KMS contract** is correct - that a signature actually produced by KMS verifies against the public key we cache, and that a real `Encrypt`/`Decrypt` round-trip behaves as the provider assumes. The `composer test:aws` tier is a small backstop for exactly that. It is **opt-in, tiny (about five tests), and never part of `composer test`**. Its single most valuable assertion is that a live-KMS ECDSA signature verifies against our cached PEM - the one thing no mock can tell us.

It is off by default and skips cleanly with an explanatory message when unconfigured. To run it, copy `.env.example` to `.env` (gitignored) and set:

- `KMS_AWS_TESTS=1` - the opt-in flag. With it unset, `composer test:aws` skips every test rather than erroring. With it **set but keys missing**, the tier fails loudly - a half-configured run is a bug, not a silent skip.
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_DEFAULT_REGION` - credentials scoped to just the two test keys below (`kms:Sign`, `kms:Encrypt`, `kms:Decrypt`, `kms:DescribeKey`).
- `KMS_TEST_SIGNING_KEY_ARN` - an **asymmetric ECC_NIST_P256** key with usage **SIGN_VERIFY**.
- `KMS_TEST_SIGNING_PUBLIC_KEY` - that key's public key, as an inline PEM or a path to a `.pem` file.
- `KMS_TEST_ENCRYPTION_KEY_ARN` - a **symmetric** key with usage ENCRYPT_DECRYPT.

The tests use **pre-existing keys that you create out of band and manage yourself**. They never create keys, and they **never call `ScheduleKeyDeletion`** - that action enforces a 7-30 day window and, once it completes, everything encrypted under the key is permanently unrecoverable. Key lifecycle is deliberately the operator's responsibility, kept out of the test run to avoid both that irreversible footgun and the cost and latency of create/schedule churn. Plaintext DEKs, as everywhere in this package, are never logged or persisted.

In CI this tier runs **only on push to `main` and on a nightly schedule - never on `pull_request`**, because fork PRs cannot read the secrets it needs and would otherwise show red checks to external contributors. The unit, PHPStan, and Pint jobs still cover every push and PR, forks included. The job is gated on the opt-in secret, so it stays green (skipping) if the secrets are absent.

**LocalStack is intentionally not used, and should not be added.** Its KMS emulates the API but does not perform trustworthy HSM-backed cryptography, so for a crypto package it would cost real infrastructure to produce coverage weaker than the existing mocks on the one axis that matters - whether real KMS crypto is compatible with our local verification. If you find a `docker-compose.yml` or LocalStack scaffolding, do not wire it in.

If you're adding behavior whose correctness genuinely depends on further real KMS semantics - key policies, grants, signing-algorithm edge cases - raise it in an issue before expanding the tier; keeping it tiny is deliberate.

## What good tests look like here

New behavior needs a test; bug fixes need a test that fails before the change and passes after. For this package, prioritize the failure and safety cases:

- **Round-trips.** `wrap()` then `unwrap()` returns the identical DEK plaintext; `sign()` then `verify()` accepts a valid signature.
- **KMS returned nothing usable.** Both providers already throw when KMS omits the expected field (`CiphertextBlob`, `Plaintext`, `Signature`) - keep that covered. A revoked or disabled key must surface as a loud failure, never as empty or partial output that a caller might treat as success.
- **Malformed input.** `unwrap()` rejects non-base64 wrapped material; missing required config (`key`, `key_arn`, `public_key`) throws at construction.
- **Verification is local and honest.** `verify()` returns false for a tampered payload, and does so without a network call - the existing signing tests assert exactly this; don't let a change quietly turn verification into a KMS round-trip or, worse, a no-op that always passes.
- **No key material in error paths.** A test asserting that a thrown exception's message contains no DEK or key bytes is worth writing.

A test proving the happy path works is worth less than a test proving a revoked key or a tampered payload can't produce output that looks valid. Write both; prioritize the second.

## Standards

Same as the rest of the org, all enforced by `composer test` and in CI:

- **Pest** - the suite must pass.
- **PHPStan level 10** - no new baseline entries.
- **Pint** - style is automated; run `composer lint` and don't hand-tune.

## Pull requests

Branch from `main`, one concern per branch, and describe the *why*. Note breaking changes explicitly.

If your change affects how KMS custody is configured or what guarantees it provides, update the docs at [laravel-chronicle.dev](https://laravel-chronicle.dev) too. For this package the docs are what a security reviewer reads to decide whether the key-custody and signing story satisfies their controls - treat a behavior change with unchanged docs as incomplete.

## Questions

[Discussions](https://github.com/orgs/laravel-chronicle/discussions), especially the compliance-shaped ones. "My auditor wants the signing key in an HSM-backed KMS with rotation - does `AwsKmsSigningProvider` satisfy that?" is exactly the kind of thread that turns into better documentation.
