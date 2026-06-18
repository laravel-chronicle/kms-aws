<?php

namespace Chronicle\KmsAws;

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
    private string $keyId;

    private string $kekId;

    private KmsClient $kms;

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
        $result = $this->kms->encrypt([
            'KeyId' => $this->keyId,
            'Plaintext' => $dek,
        ]);

        $blob = $result->get('CiphertextBlob');

        if (! is_string($blob)) {
            throw new RuntimeException('KMS Encrypt did not return a CiphertextBlob.');
        }

        return base64_encode($blob);
    }

    public function unwrap(string $wrapped): string
    {
        $blob = base64_decode($wrapped, true);

        if ($blob === false) {
            throw new InvalidArgumentException('Wrapped DEK is not valid base64.');
        }

        $result = $this->kms->decrypt([
            'KeyId' => $this->keyId,
            'CiphertextBlob' => $blob,
        ]);

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
}
