<?php

use BYU\JWT\BYUJWT;
use PHPUnit\Framework\TestCase;

/**
 * @covers BYUJWT
 */
final class BYUJWTTest extends TestCase
{
    public function testModifyWellKnownHost()
    {
        $alternateWellKnownHost = "http://fake.com";
        BYUJWT::setWellKnownHost($alternateWellKnownHost);
        $this->assertEquals($alternateWellKnownHost, BYUJWT::$wellKnownHost);
    }

    public function testInvalidJWTReturnError()
    {
        //Using assertSame instead of assertEquals in this case, because
        //we want to ensure actual boolean "false" instead of "falsy" values
        //like void, null, 0, etc.
        $this->assertSame(false, BYUJWT::verifyJWT("Um, some bad JWT here"));
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
        $this->assertSame(false, BYUJWT::verifyJWT("Seemingly good JWT with no expiration"));
    }

    public function testHeaderConstants()
    {
        $this->assertEquals(BYUJWT::BYU_JWT_HEADER_CURRENT, "X-JWT-Assertion");
        $this->assertEquals(BYUJWT::BYU_JWT_HEADER_ORIGINAL, "X-JWT-Assertion-Original");
    }

    public function testJTWVerifySuccesful()
    {
        //Verify false when JWT Expiration does not exist
        $this->assertSame(false, BYUJWT::verifyJWT("Good JWT", "Well-known URL here"));
        $this->assertSame(false, BYUJWT::verifyJWT("Good JWT"));

    public function testJTWDecodeSuccesful()
    {
				$decodedJwt = BYUJWT::jwtDecoded("Good JWT", "Well-known UTL here");
				$this->assertSame("649019965", $decodedJwt.byu.client.byuId);
				$this->assertSame("CLIENT_SUBSCRIBER", $decodedJwt.byu.client.claim_source);
				$this->assertSame("adddrop", $decodedJwt.byu.client.netId);
				$this->assertSame("377228062", $decodedJwt.byu.client.personId);
				$this->assertSame("Add", $decodedJwt.byu.client.preferredFirstName);
				$this->assertSame(" ", $decodedJwt.byu.client.prefix);
				$this->assertSame("Add", $decodedJwt.byu.client.restOfName);
				$this->assertSame("Drop, Add", $decodedJwt.byu.client.sortName);
				$this->assertSame("adddrop", $decodedJwt.byu.client.subscriberNetId);
				$this->assertSame(" ", $decodedJwt.byu.client.suffix);
				$this->assertSame("Drop", $decodedJwt.byu.client.surname);
				$this->assertSame("L", $decodedJwt.byu.client.surnamePosition);
				#$this->assertSame("adddrop", $decodedJwt.byu.resourceOwner.byuId);
				#$this->assertSame("adddrop", $decodedJwt.byu.resourceOwner.netId);
				#$this->assertSame("adddrop", $decodedJwt.byu.resourceOwner.personId);
				#$this->assertSame("adddrop", $decodedJwt.byu.resourceOwner.preferredFirstName);
				#$this->assertSame("adddrop", $decodedJwt.byu.resourceOwner.prefix);
				#$this->assertSame("adddrop", $decodedJwt.byu.resourceOwner.restOfName);
				#$this->assertSame("adddrop", $decodedJwt.byu.resourceOwner.sortName);
				#$this->assertSame("adddrop", $decodedJwt.byu.resourceOwner.suffix);
				#$this->assertSame("adddrop", $decodedJwt.byu.resourceOwner.surname);
				#$this->assertSame("adddrop", $decodedJwt.byu.resourceOwner.surnamePosition);
				$this->assertSame("649019965", $decodedJwt.byu.webResCheck.byuId);
				$this->assertSame("adddrop", $decodedJwt.byu.webResCheck.netId);
				$this->assertSame("377228062", $decodedJwt.byu.webResCheck.personId);
				$this->assertSame("/echo/v1", $decodedJwt.wso2.apiContext);
				$this->assertSame("2085", $decodedJwt.wso2.application.id);
				$this->assertSame("DefaultApplication", $decodedJwt.wso2.application.name);
				$this->assertSame("Unlimited", $decodedJwt.wso2.application.tier);
				$this->assertSame("5gzLjMUcx7qut3MuSf9xr8GV2BAa", $decodedJwt.wso2.clientId);
				$this->assertSame("adddrop@carbon.super", $decodedJwt.wso2.endUser);
				$this->assertSame("-1234", $decodedJwt.wso2.endUserTenantId);
				$this->assertSame("PRODUCTION", $decodedJwt.wso2.keyType);
				$this->assertSame("BYU/adddrop", $decodedJwt.wso2.subscriber);
				$this->assertSame("Bronze", $decodedJwt.wso2.tier);
				$this->assertSame("APPLICATION", $decodedJwt.wso2.userType);
				$this->assertSame("v1", $decodedJwt.wso2.version);
    }
}
