<?php

declare(strict_types=1);

namespace Chronicle\KmsAws\Tests;

use Chronicle\KmsAws\KmsAwsServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    /**
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            KmsAwsServiceProvider::class,
        ];
    }
}
