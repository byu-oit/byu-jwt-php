<?php
require __DIR__ . '/../vendor/autoload.php';

\VCR\VCR::configure()->enableLibraryHooks(array('curl', 'stream_wrapper'));
