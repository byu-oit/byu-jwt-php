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
  
    public function testJWTWithNoExpiration()
    {
        //Verify false when JWT Expiration does not exist
        $this->assertSame(false, BYUJWT::verifyJWT("Seemingly good JWT with no expiration", "Well-known URL here"));
    }
}