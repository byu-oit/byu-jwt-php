<?php

use BYU\JWT\BYUJWT;
use PHPUnit\Framework\TestCase;

/**
 * @covers BYUJWT
 */
final class BYUJWTTest extends TestCase
{
    public function testInvalidJWTReturnError()
    {
        //Using assertSame instead of assertEquals in this case, because
        //we want to ensure actual boolean "false" instead of "falsy" values
        //like void, null, 0, etc.
        $this->assertSame(false, BYUJWT::verifyJWT("Um, some bad JWT here", "Well-known URL here"));
    }
}