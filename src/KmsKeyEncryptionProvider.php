<?php

declare(strict_types=1);

namespace Chronicle\KmsAws;

use Aws\Exception\AwsException;
use Aws\Kms\KmsClient;
use Chronicle\Contracts\KeyEncryptionProvider;
use InvalidArgumentException;
use RuntimeException;

/**
 * KMS-backed KEK provider for Chronicle crypto-shredding. Wraps/unwraps per-subject
 * DEKs through AWS KMS Encrypt/Decrypt, so the KEK never leaves the HSM. Reads the
 * same config shape as the local provider (`key` = KMS key ARN/ID, `id` = kekId
 * recorded per subject key), and is resolved by KeyEncryptionManager::providerFor()
 * via the container's makeWith (the KmsClient is auto-injected).
 *
 * Config keys:
 *   key - KMS key ARN or id used for Encrypt/Decrypt (required)
 *   id  - Chronicle kekId stored in subject_keys.kek_id (optional, defaults to the key)
 *
 * Required IAM actions on the KEK: kms:Encrypt, kms:Decrypt.
 */
final class KmsKeyEncryptionProvider implements KeyEncryptionProvider
{
    protected string $keyId;

    protected string $kekId;

    protected KmsClient $kms;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(array $config, KmsClient $client)
    {
        $key = $config['key'] ?? null;

        if (! is_string($key) || $key === '') {
            throw new InvalidArgumentException(
                'Missing key for KmsKeyEncryptionProvider - provide the KMS key ARN or id.'
            );
        }

        $this->keyId = $key;

        $id = $config['id'] ?? null;
        $this->kekId = is_string($id) && $id !== '' ? $id : $key;

        $this->kms = $client;
    }

    public function wrap(string $dek): string
    {
        try {
            $result = $this->kms->encrypt([
                'KeyId' => $this->keyId,
                'Plaintext' => $dek,
            ]);
        } catch (AwsException $e) {
            throw $this->sanitizeKmsException('Encrypt', $e);
        }

        $blob = $result->get('CiphertextBlob');

        if (! is_string($blob)) {
            throw new RuntimeException('KMS Encrypt did not return a CiphertextBlob.');
        }

        return base64_encode($blob);
    }

    /**
     * Unwrap a wrapped DEK back to its plaintext bytes via KMS Decrypt.
     *
     * SECURITY - the returned string is live plaintext key material. Its lifetime
     * is the caller's responsibility: it cannot be scrubbed here because it is the
     * return value the caller needs. The caller MUST NOT log, persist, serialize,
     * var_dump, or otherwise copy it, and SHOULD zero it (e.g. sodium_memzero()
     * where available) as soon as the DEK has been used. Nothing inside this
     * method retains plaintext beyond return - the only sensitive intermediates
     * are the SDK Result (owned by the AWS SDK) and this return value.
     */
    public function unwrap(string $wrapped): string
    {
        $blob = base64_decode($wrapped, true);

        if ($blob === false) {
            throw new InvalidArgumentException('Wrapped DEK is not valid base64.');
        }

        try {
            $result = $this->kms->decrypt([
                'KeyId' => $this->keyId,
                'CiphertextBlob' => $blob,
            ]);
        } catch (AwsException $e) {
            throw $this->sanitizeKmsException('Decrypt', $e);
        }

        $plaintext = $result->get('Plaintext');

        if (! is_string($plaintext)) {
            throw new RuntimeException('KMS Decrypt did not return a Plaintext value.');
        }

        return $plaintext;
    }

    public function kekId(): string
    {
        return $this->kekId;
    }

    /**
     * Rethrow an AWS SDK failure as a sanitized RuntimeException.
     *
     * SECURITY - the original AwsException retains the KMS command via getCommand(),
     * which for Encrypt still holds the plaintext DEK. We therefore do NOT chain it
     * as $previous: that would keep the plaintext reachable through getPrevious().
     * Only the operation name and the AWS error code (safe, non-sensitive metadata)
     * are preserved.
     */
    protected function sanitizeKmsException(string $operation, AwsException $e): RuntimeException
    {
        $code = $e->getAwsErrorCode();
        $suffix = is_string($code) && $code !== '' ? " ($code)" : '';

        return new RuntimeException("KMS $operation failed$suffix.");
    }
}
