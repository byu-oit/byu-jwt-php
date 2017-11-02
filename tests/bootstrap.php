<?php
require __DIR__ . '/../vendor/autoload.php';

//Need to ignore headers when matching requests, so that Guzzle's environment-specific
//"User-Agent" headers do not interfere
//In fact, for our particular use we *only* need the target URL to uniquely identify
//a particular request.
//Also, we don't need php-vcr's SOAP or stream_wrapper hooks
\VCR\VCR::configure()
    ->enableRequestMatchers(['url'])
    ->enableLibraryHooks(['curl']);
