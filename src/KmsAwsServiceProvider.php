<?php

declare(strict_types=1);

namespace Chronicle\KmsAws;

use Aws\Kms\KmsClient;
use Illuminate\Support\ServiceProvider;

/**
 * Registers a KmsClient singleton shaped from the chronicle-kms config.
 *
 * Config keys (config/chronicle-kms.php):
 *   region   - KMS endpoint region (env AWS_DEFAULT_REGION, default 'us-east-1')
 *   endpoint - optional custom endpoint for LocalStack / KMS FIPS (env
 *              CHRONICLE_KMS_ENDPOINT); when unset, no endpoint is passed and the
 *              SDK derives it from the region
 *   version  - KMS API version (env CHRONICLE_KMS_VERSION, default 'latest')
 *
 * Environment variables for credentials (never read from config - they flow
 * through the standard AWS credential chain):
 *   AWS_ACCESS_KEY_ID     - AWS credentials (omit when using EC2/ECS IAM roles)
 *   AWS_SECRET_ACCESS_KEY
 *
 * For anything the config keys do not cover - a custom credential provider, or a
 * fully custom client - re-bind Aws\Kms\KmsClient in your application's
 * AppServiceProvider. That binding wins as long as it registers after this
 * provider (the normal case for an app service provider), since the last
 * singleton binding for a given abstract is the one the container resolves.
 */
class KmsAwsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/chronicle-kms.php', 'chronicle-kms');

        $this->app->singleton(KmsClient::class, function (): KmsClient {
            /** @var string $region */
            $region = config('chronicle-kms.region', 'us-east-1');

            /** @var string $version */
            $version = config('chronicle-kms.version', 'latest');

            $args = [
                'region' => $region,
                'version' => $version,
            ];

            /** @var string|null $endpoint */
            $endpoint = config('chronicle-kms.endpoint');

            // Only include 'endpoint' when explicitly set - a present-but-null
            // endpoint is treated differently from an absent one by some SDK
            // versions, so leave it out entirely for normal AWS use.
            if (is_string($endpoint) && $endpoint !== '') {
                $args['endpoint'] = $endpoint;
            }

            return new KmsClient($args);
        });
    }
}
