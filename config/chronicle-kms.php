<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | KMS region
    |--------------------------------------------------------------------------
    |
    | The AWS region whose KMS endpoint the client talks to. Defaults to the
    | standard AWS region environment variable.
    |
    */
    'region' => env('AWS_DEFAULT_REGION', 'us-east-1'),

    /*
    |--------------------------------------------------------------------------
    | KMS endpoint (optional)
    |--------------------------------------------------------------------------
    |
    | Override the KMS endpoint the client connects to. Leave unset for normal
    | AWS use - the SDK derives the correct endpoint from the region. Set it to
    | point at LocalStack (e.g. http://localhost:4566) for testing, or at a KMS
    | FIPS endpoint (e.g. https://kms-fips.<region>.amazonaws.com) for regulated
    | deployments. When null/absent, no endpoint is passed to the client.
    |
    */
    'endpoint' => env('CHRONICLE_KMS_ENDPOINT'),

    /*
    |--------------------------------------------------------------------------
    | KMS API version
    |--------------------------------------------------------------------------
    |
    | The AWS KMS API version the client is pinned to. 'latest' tracks the SDK's
    | newest bundled version; pin to a dated version (e.g. '2014-11-01') if you
    | need a fixed API contract.
    |
    */
    'version' => env('CHRONICLE_KMS_VERSION', 'latest'),
];
