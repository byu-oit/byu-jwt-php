<?php

use BYU\JWT\BYUJWT;
use PHPUnit\Framework\TestCase;

/**
 * @covers BYUJWT
 */
final class BYUJWTTest extends TestCase
{
    public function testModifyWellKnown()
    {
        $alternateWellKnownURL = "http://fake.com/alternate-well-known";
        BYUJWT::setWellKnown($alternateWellKnownURL);
        $this->assertEquals($alternateWellKnownURL, BYUJWT::$wellKnownURL);
    }

    public function testInvalidJWTReturnError()
    {
        //Using assertSame instead of assertEquals in this case, because
        //we want to ensure actual boolean "false" instead of "falsy" values
        //like void, null, 0, etc.
        $this->assertSame(false, BYUJWT::verifyJWT("Um, some bad JWT here", "Well-known URL here"));
    }

    public function testExpiredJWTReturnError()
    {
        // Expired JWT for a bot user
        $expiredJWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlpUUm1NMk5tWkRabFlUZG1aRFJqWVdJME1tTXpZamd4WWpNd1lXUXhNems0TnpFd09EVmxNdyJ9.eyJpc3MiOiJodHRwczovL2FwaS5ieXUuZWR1IiwiZXhwIjoxNDg5NzY4MTczLCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL3N1YnNjcmliZXIiOiJCWVUvYWRkZHJvcCIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvYXBwbGljYXRpb25pZCI6IjIwODUiLCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL2FwcGxpY2F0aW9ubmFtZSI6IkRlZmF1bHRBcHBsaWNhdGlvbiIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvYXBwbGljYXRpb250aWVyIjoiVW5saW1pdGVkIiwiaHR0cDovL3dzbzIub3JnL2NsYWltcy9hcGljb250ZXh0IjoiL2VjaG8vdjEiLCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL3ZlcnNpb24iOiJ2MSIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvdGllciI6IkJyb256ZSIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMva2V5dHlwZSI6IlBST0RVQ1RJT04iLCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL3VzZXJ0eXBlIjoiQVBQTElDQVRJT04iLCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL2VuZHVzZXIiOiJhZGRkcm9wQGNhcmJvbi5zdXBlciIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvZW5kdXNlclRlbmFudElkIjoiLTEyMzQiLCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL2NsaWVudF9pZCI6IjVnekxqTVVjeDdxdXQzTXVTZjl4cjhHVjJCQWEiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X3Jlc3Rfb2ZfbmFtZSI6IkFkZCIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9jbGllbnRfcGVyc29uX2lkIjoiMzc3MjI4MDYyIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL2NsaWVudF9zb3J0X25hbWUiOiJEcm9wLCBBZGQiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X2NsYWltX3NvdXJjZSI6IkNMSUVOVF9TVUJTQ1JJQkVSIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL2NsaWVudF9uZXRfaWQiOiJhZGRkcm9wIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL2NsaWVudF9zdWJzY3JpYmVyX25ldF9pZCI6ImFkZGRyb3AiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X25hbWVfc3VmZml4IjoiICIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9jbGllbnRfc3VybmFtZSI6IkRyb3AiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X3N1cm5hbWVfcG9zaXRpb24iOiJMIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL2NsaWVudF9uYW1lX3ByZWZpeCI6IiAiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X2J5dV9pZCI6IjY0OTAxOTk2NSIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9jbGllbnRfcHJlZmVycmVkX2ZpcnN0X25hbWUiOiJBZGQifQ.luAysmbldL0Hn1PO1TeHSba79tiVwnaEFLPMknsX5xegqExrJXs_FEge8R7PWj-KnjCMZt1QZbUeDz9boBWednXORSIHOk8TIZzM1hc3kM883sQXRbe9hiTfnoWf0zN2i9B6LBV1vqSFgJu7-PP_kAk0E1kfi7TcbWjecYc9H6vBijHrguh-WvwLuHg5qjC7en-FWcoYO_yM1oWvNajrUUdFbW6WC7lgkvnAPqreNlCuRA23uk45incuMNyFtldlMVOtAsqxRFgpydnujmnuP-l8gU2L1zFXdOkj-gTmq4v-sMCS2crrYW4MIVy5ObqlsQMOisjqturQLuxLo9fYpQ";

        $this->assertSame(false, BYUJWT::verifyJWT($expiredJWT, "https://api.byu.edu"));
    }

    public function testJWTWithNoExpiration()
    {
        //Verify false when JWT Expiration does not exist
        $this->assertSame(false, BYUJWT::verifyJWT("Seemingly good JWT with no expiration", "Well-known URL here"));
    }
}
