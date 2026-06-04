<?php

namespace Chronicle\KmsAws;

use Aws\Kms\KmsClient;
use Illuminate\Support\ServiceProvider;

/**
 * Registers a KmsClient singleton resolved from environment variables.
 *
 * Environment variables:
 *   AWS_DEFAULT_REGION    - KMS endpoint region (e.g. 'eu-west-1')
 *   AWS_ACCESS_KEY_ID     - AWS credentials (omit when using EC2/ECS IAM roles)
 *   AWS_SECRET_ACCESS_KEY
 *
 * To override the KmsClient binding (e.g. for custom credential providers),
 * re-bind Aws\Kms\KmsClient in your application's AppServiceProvider.
 */
class KmsAwsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/chronicle-kms.php', 'chronicle-kms');

        $this->app->singleton(KmsClient::class, function (): KmsClient {
            /** @var string $region */
            $region = config('chronicle-kms.region', 'us-east-1');

            return new KmsClient([
                'region' => $region,
                'version' => 'latest',
            ]);
        });
    }
}
