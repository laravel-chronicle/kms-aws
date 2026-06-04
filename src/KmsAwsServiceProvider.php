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
        $this->app->singleton(KmsClient::class, function (): KmsClient {
            return new KmsClient([
                'region' => (string) env('AWS_DEFAULT_REGION', 'us-east-1'),
                'version' => 'latest',
            ]);
        });
    }
}
