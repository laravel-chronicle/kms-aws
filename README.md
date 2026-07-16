# laravel-chronicle/kms-aws

[![Tests](https://github.com/laravel-chronicle/kms-aws/actions/workflows/run-tests.yml/badge.svg)](https://github.com/laravel-chronicle/kms-aws/actions/workflows/run-tests.yml)
[![PHPStan](https://github.com/laravel-chronicle/kms-aws/actions/workflows/phpstan.yml/badge.svg)](https://github.com/laravel-chronicle/kms-aws/actions/workflows/phpstan.yml)
[![Latest Version](https://img.shields.io/packagist/v/laravel-chronicle/kms-aws.svg)](https://packagist.org/packages/laravel-chronicle/kms-aws)
[![Total Downloads](https://img.shields.io/packagist/dt/laravel-chronicle/kms-aws.svg)](https://packagist.org/packages/laravel-chronicle/kms-aws)
[![License](https://img.shields.io/packagist/l/laravel-chronicle/kms-aws.svg)](LICENSE)

AWS KMS custody for the [Chronicle audit ledger](https://github.com/laravel-chronicle/core).

Keeps Chronicle's cryptographic key material inside AWS KMS instead of on the
application server. The package provides two independent providers:

- **Signing** (`AwsKmsSigningProvider`) - signs checkpoints and exports via KMS (ECDSA P-256). Verification is always **offline**, using a cached public key, so no AWS call is needed to verify.
- **KEK custody** (`KmsKeyEncryptionProvider`) - holds the Key Encryption Key for Chronicle's crypto-shredding, wrapping and unwrapping per-subject DEKs through KMS `Encrypt`/`Decrypt` so the KEK never leaves the HSM.

Use either or both. The signing setup is covered first; KEK custody has its own section below.

---

## Installation

```bash
composer require laravel-chronicle/kms-aws
```

The package auto-discovers its service provider via Laravel's package discovery.

---

## Requirements

- PHP 8.2+
- `ext-openssl`
- `laravel-chronicle/core` ^1.10
- AWS SDK for PHP ^3.0

---

## AWS Setup

> This section sets up the **signing** provider. If you also want KEK custody for crypto-shredding, you'll need a separate **symmetric** key - see [KEK encryption provider](#kek-encryption-provider-crypto-shredding) below. The two providers use different key types and are configured independently.

### Create a KMS key (signing)

Create an asymmetric KMS key with:
- **Key type:** Asymmetric
- **Key spec:** ECC_NIST_P256
- **Key usage:** SIGN_VERIFY

### Required IAM actions

Attach the following IAM policy to the role that runs your application:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Sign",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID"
    }
  ]
}
```

`kms:GetPublicKey` is **not** required at runtime - the public key is cached in your application config and never fetched from KMS during verification.

### Retrieve and cache the public key

Retrieve your KMS key's public key once and store it in your config:

```bash
aws kms get-public-key \
  --key-id arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID \
  --query 'PublicKey' --output text | base64 -d | \
  openssl pkey -pubin -inform DER -outform PEM
```

This outputs a PEM string like:

```
-----BEGIN PUBLIC KEY-----
MFkwEwYH...
-----END PUBLIC KEY-----
```

Store this as the `public_key` in your Chronicle signing config (see below).

---

## Configuration

Register the KMS key in `config/chronicle.php` under `signing.keys`:

```php
use Chronicle\KmsAws\AwsKmsSigningProvider;

'signing' => [
    'active' => env('CHRONICLE_ACTIVE_KEY', 'kms-production'),

    'keys' => [
        'kms-production' => [
            'provider'   => AwsKmsSigningProvider::class,
            'algorithm'  => 'ecdsa-p256',
            'key_arn'    => env('CHRONICLE_KMS_KEY_ARN'),
            'public_key' => env('CHRONICLE_KMS_PUBLIC_KEY'),  // PEM string
        ],
    ],
],
```

Set the corresponding environment variables:

```dotenv
AWS_DEFAULT_REGION=eu-west-1
CHRONICLE_ACTIVE_KEY=kms-production
CHRONICLE_KMS_KEY_ARN=arn:aws:kms:eu-west-1:123456789012:key/your-key-id
CHRONICLE_KMS_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----
"
```

---

## How it works

| Operation  | Where it runs                                                  |
|------------|----------------------------------------------------------------|
| `sign()`   | **Remote** - calls KMS `Sign` API with `MessageType: DIGEST`   |
| `verify()` | **Local** - `openssl_verify` against the cached PEM public key |

The private key never leaves AWS KMS. Verification is offline and instant.

---

## Key rotation

Chronicle's key rotation works identically for KMS-backed keys. Retire the old key by
keeping only its `public_key` in the ring (omit `key_arn`), then add the new KMS key as
active. Historic checkpoints and exports continue to verify offline against the retained
public key.

Example two-key ring after rotation:

```php
'signing' => [
    'active' => 'kms-2026',
    'keys' => [
        // Retired - switch to EcdsaSigningProvider (from core) for verify-only mode.
        // AwsKmsSigningProvider requires key_arn and cannot be verify-only.
        'kms-2025' => [
            'provider'   => \Chronicle\Signing\EcdsaSigningProvider::class,
            'algorithm'  => 'ecdsa-p256',
            'public_key' => env('CHRONICLE_KMS_2025_PUBLIC_KEY'),
        ],
        // Active
        'kms-2026' => [
            'provider'   => AwsKmsSigningProvider::class,
            'algorithm'  => 'ecdsa-p256',
            'key_arn'    => env('CHRONICLE_KMS_KEY_ARN'),
            'public_key' => env('CHRONICLE_KMS_PUBLIC_KEY'),
        ],
    ],
],
```

> **Note:** `AwsKmsSigningProvider` requires `key_arn` at construction - it cannot be used as a verify-only provider. For retired KMS keys, switch the entry to `Chronicle\Signing\EcdsaSigningProvider` (from core) with only `public_key` set, as shown above. Core's `EcdsaSigningProvider` handles the local-verify-only case.

---

## KEK encryption provider (crypto-shredding)

Chronicle v1.12 can encrypt PII payload fields under a per-subject DEK, wrapping
those DEKs under a Key Encryption Key (KEK). This package can hold the KEK in
AWS KMS so wrapped DEKs are protected outside the application.

Point `chronicle.encryption.kek` at the KMS provider:

```php
// config/chronicle.php
use Chronicle\KmsAws\KmsKeyEncryptionProvider;

'encryption' => [
    'enabled' => true,
    'kek' => [
        'provider' => KmsKeyEncryptionProvider::class,
        'key' => env('CHRONICLE_KMS_KEK_ARN'),   // KMS key ARN/id for Encrypt/Decrypt
        'id'  => env('CHRONICLE_KMS_KEK_ID'),     // kekId recorded per subject key
    ],
],
```

Required IAM actions on the KEK: `kms:Encrypt`, `kms:Decrypt`. The `KmsClient` is
resolved from the container (region from `AWS_DEFAULT_REGION`), so no extra wiring
is needed beyond installing this package.

### KmsClient options

The `KmsClient` singleton is shaped from `config/chronicle-kms.php`. All keys have sensible defaults - set nothing, and you get a standard region-derived client.

```dotenv
# Region the KMS client talks to (standard AWS variable)
AWS_DEFAULT_REGION=eu-west-1

# Optional: override the KMS endpoint. Leave unset for normal AWS use.
# Point at LocalStack for testing, or a KMS FIPS endpoint for regulated deployments.
CHRONICLE_KMS_ENDPOINT=http://localhost:4566
# CHRONICLE_KMS_ENDPOINT=https://kms-fips.eu-west-1.amazonaws.com

# Optional: pin the KMS API version (defaults to 'latest')
CHRONICLE_KMS_VERSION=latest
```

Credentials are never read from this config - they flow through the standard AWS credential chain (env vars, IAM roles, etc.). For anything these keys don't cover - a custom credential provider, or a fully custom client - re-bind `Aws\Kms\KmsClient` in your application's `AppServiceProvider`; that binding wins over this provider's default.

---

## License

MIT
