<?php

declare(strict_types=1);

namespace Chronicle\KmsAws;

use Aws\Exception\AwsException;
use Aws\Kms\KmsClient;
use Chronicle\Signing\LocalVerifyProvider;
use InvalidArgumentException;
use RuntimeException;

/**
 * AWS KMS signing provider for Chronicle.
 *
 * sign()   - sends SHA256(payload) to KMS Sign API (DIGEST mode, ECDSA_SHA_256).
 * verify() - validates locally via LocalVerifyProvider using a cached PEM public key.
 *            No network call required for verification.
 *
 * Config keys:
 *   key_arn    - KMS key ARN used for signing (required)
 *   public_key - PEM-encoded EC public key for local verification (required)
 *   key_id     - Chronicle key identifier stored in checkpoints/exports (optional, defaults to 'none')
 *   region     - AWS region (optional; KmsClient binding in KmsAwsServiceProvider uses AWS_DEFAULT_REGION)
 *
 * Required IAM actions on the signing key:
 *   kms:Sign
 *   kms:DescribeKey (for health checks)
 */
class AwsKmsSigningProvider extends LocalVerifyProvider
{
    protected string $keyArn;

    protected string $publicPem;

    protected string $keyId;

    protected KmsClient $kms;

    /**
     * @param  array{key_arn?: string|null, public_key?: string|null, key_id?: string|null}  $config
     */
    public function __construct(array $config, KmsClient $client)
    {
        $keyArn = $config['key_arn'] ?? null;

        if (! is_string($keyArn) || $keyArn === '') {
            throw new InvalidArgumentException(
                'Missing key_arn for AwsKmsSigningProvider - provide the KMS key ARN.'
            );
        }

        $publicKey = $config['public_key'] ?? null;

        if (! is_string($publicKey) || $publicKey === '') {
            throw new InvalidArgumentException(
                'Missing public_key for AwsKmsSigningProvider - provide a PEM-encoded EC public key.'
            );
        }

        $this->keyArn = $keyArn;
        $this->publicPem = $publicKey;
        $this->keyId = $config['key_id'] ?? 'none';
        $this->kms = $client;
    }

    public function sign(string $payload): string
    {
        $digest = hash('sha256', $payload, true);

        try {
            $result = $this->kms->sign([
                'KeyId' => $this->keyArn,
                'Message' => $digest,
                'MessageType' => 'DIGEST',
                'SigningAlgorithm' => 'ECDSA_SHA_256',
            ]);
        } catch (AwsException $e) {
            throw $this->sanitizeKmsException('Sign', $e);
        }

        $signature = $result->get('Signature');

        if (! is_string($signature)) {
            throw new RuntimeException('KMS Sign API did not return a Signature value.');
        }

        return base64_encode($signature);
    }

    /**
     * Rethrow an AWS SDK failure as a sanitized RuntimeException.
     *
     * SECURITY - the original AwsException retains the KMS command via getCommand().
     * We do NOT chain it as $previous, so no raw AWS request context propagates.
     * Only the operation name and the AWS error code (safe metadata) are preserved.
     */
    protected function sanitizeKmsException(string $operation, AwsException $e): RuntimeException
    {
        $code = $e->getAwsErrorCode();
        $suffix = is_string($code) && $code !== '' ? " ($code)" : '';

        return new RuntimeException("KMS $operation failed$suffix.");
    }

    public function algorithm(): string
    {
        return 'ecdsa-p256';
    }

    public function keyId(): ?string
    {
        return $this->keyId;
    }

    protected function cachedPublicKeyPem(): string
    {
        return $this->publicPem;
    }
}
