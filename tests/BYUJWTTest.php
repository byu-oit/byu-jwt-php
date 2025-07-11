<?php
/* Copyright 2017 Brigham Young University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

namespace BYU\JWT\Test;

use BYU\JWT\BYUJWT;
use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;

/**
 * Using PHP-VCR to mock network requests.
 * For these mock network requests, we replaced the actual BYU public key
 * with a self-generated key using the included "testing.key" private key.
 * This allows us to generate "valid" JWT data for these tests without
 * requiring the inclusion of the real BYU private key
 *
 * @covers \BYU\JWT\BYUJWT
 */
final class BYUJWTTest extends TestCase
{

    protected static $privateKey;

    public static function setUpBeforeClass()
    {
        $keyData = file_get_contents(dirname(__FILE__) . '/testing.key');
        static::$privateKey = openssl_pkey_get_private($keyData);
    }

    public function setUp()
    {
        $this->BYUJWT = new BYUJWT();

        parent::setUp();
    }

    /**
     * @vcr ok_wellknown_and_jwks.yml
     */
    public function testJwtDecode()
    {
        $jwt = JWT::encode(
            ['iss' => 'https://api.byu.edu', 'exp' => time() + 10, 'data' => 'test'],
            static::$privateKey, 'RS256'
        );
        $decodedJwt = $this->BYUJWT->decode($jwt);
        $this->assertNotEmpty($decodedJwt);
        $this->assertEquals('https://api.byu.edu', $decodedJwt['iss']);
        $this->assertEquals('test', $decodedJwt['data']);
    }

    /**
     * @vcr ok_sandbox_wellknown_and_jwks.yml
     */
    public function testSandboxJwtDecode()
    {
        $jwt = JWT::encode(
            ['iss' => 'https://api-sandbox.byu.edu', 'exp' => time() + 10, 'data' => 'test'],
            static::$privateKey, 'RS256'
        );
        $decodedJwt = $this->BYUJWT->decode($jwt);
        $this->assertNotEmpty($decodedJwt);
        $this->assertEquals('https://api-sandbox.byu.edu', $decodedJwt['iss']);
        $this->assertEquals('test', $decodedJwt['data']);
    }

    /**
     * @vcr ok_dev_wellknown_and_jwks.yml
     */
    public function testDevJwtDecode()
    {
        $jwt = JWT::encode(
            ['iss' => 'https://api-dev.byu.edu', 'exp' => time() + 10, 'data' => 'test'],
            static::$privateKey, 'RS256'
        );
        $decodedJwt = $this->BYUJWT->decode($jwt);
        $this->assertNotEmpty($decodedJwt);
        $this->assertEquals('https://api-dev.byu.edu', $decodedJwt['iss']);
        $this->assertEquals('test', $decodedJwt['data']);
    }

    /**
     * @vcr ok_wellknown_and_jwks.yml
     */
    public function testJwtValidate()
    {
        $jwt = JWT::encode(
            ['iss' => 'https://api.byu.edu', 'exp' => time() + 10],
            static::$privateKey, 'RS256'
        );
        $this->assertSame(true, $this->BYUJWT->validateJWT($jwt));
    }

    /**
     * @vcr ok_wellknown_and_jwks.yml
     */
    public function testWellKnown()
    {
        $wellKnown = $this->BYUJWT->getWellKnown();
        $this->assertNotEmpty($wellKnown);
        $this->assertEquals($wellKnown->issuer, 'https://api.byu.edu');
    }

    /**
     * @vcr ok_old_wellknown_and_jwks.yml
     */
    public function testPublicKey()
    {
        $key = $this->BYUJWT->getPublicKey();
        $this->assertNotEmpty($key);
        $cachedKey = $this->BYUJWT->getPublicKey();
        $this->assertEquals($key, $cachedKey);
    }

    /**
     * @vcr ok_wellknown_and_jwks.yml
     */
    public function testPublicKeys()
    {
        $keys = $this->BYUJWT->getPublicKeys();
        $this->assertNotEmpty($keys);
        $cachedKeys = $this->BYUJWT->getPublicKeys();
        $this->assertEquals($keys, $cachedKeys);
    }

    /**
     * @vcr missing_wellknown.yml
     */
    public function testMissingWellKnown()
    {
        $this->assertEmpty($this->BYUJWT->getWellKnown());
        $this->assertEmpty($this->BYUJWT->getPublicKey());
        $this->assertEmpty($this->BYUJWT->getPublicKeys());
    }

    /**
     * @vcr bad_wellknown.yml
     */
    public function testBadWellKnown()
    {
        $this->assertEmpty($this->BYUJWT->getWellKnown());
    }

    public function testBadWellKnownUrl()
    {
        $BYUJWT = new BYUJWT(['wellKnownUrl' => 'badprotocol://fakeurl']);

        $this->assertEmpty($BYUJWT->getWellKnown());
        $this->assertInstanceOf(
            'GuzzleHttp\Exception\RequestException',
            $BYUJWT->lastException
        );
    }

    /**
     * @vcr missing_jwks.yml
     */
    public function testMissingJwks()
    {
        $this->assertNotEmpty($this->BYUJWT->getWellKnown());
        $this->assertEmpty($this->BYUJWT->getPublicKey());
        $this->assertEmpty($this->BYUJWT->getPublicKeys());
        $this->assertSame(false, $this->BYUJWT->validateJWT("bad JWT!"));
        $this->assertInstanceOf('Exception', $this->BYUJWT->lastException);
        $this->assertEquals('Could not decode JWT', $this->BYUJWT->lastException->getMessage());
    }

    /**
     * @vcr bad_jwks.yml
     */
    public function testBadJwks()
    {
        $this->assertNotEmpty($this->BYUJWT->getWellKnown());
        $this->assertEmpty($this->BYUJWT->getPublicKey());
        $this->assertEmpty($this->BYUJWT->getPublicKeys());
    }

    /**
     * @vcr bad_jwks_key.yml
     */
    public function testBadJwksKey()
    {
        $this->assertNotEmpty($this->BYUJWT->getWellKnown());
        $this->assertEmpty($this->BYUJWT->getPublicKey());
        $this->assertEmpty($this->BYUJWT->getPublicKeys());
    }

    public function testInvalidJWT()
    {
        //Using assertSame instead of assertEquals in this case, because
        //we want to ensure actual boolean "false" instead of "falsy" values
        //like void, null, 0, etc.
        $this->assertSame(false, $this->BYUJWT->validateJWT("bad JWT!"));
        $this->assertInstanceOf('Exception', $this->BYUJWT->lastException);
    }

    /**
     * @vcr ok_wellknown_and_jwks.yml
     */
    public function testExpiredJWT()
    {
        $jwt = JWT::encode(
            ['iss' => 'https://api.byu.edu', 'exp' => 1],
            static::$privateKey, 'RS256'
        );

        $this->assertSame(false, $this->BYUJWT->validateJWT($jwt));
        $this->assertInstanceOf(
            'Firebase\JWT\ExpiredException',
            $this->BYUJWT->lastException
        );
    }

    /**
     * @vcr ok_wellknown_and_jwks.yml
     */
    public function testUnallowedAlgorithm()
    {
        //JWT::encode default algorithm is "HS256"
        $badJwt = JWT::encode(['data' => 'testdata'], 'dummy key');
        $this->assertSame(false, $this->BYUJWT->validateJWT($badJwt));
        $this->assertEquals(
            'Algorithm not allowed',
            $this->BYUJWT->lastException->getMessage()
        );
    }

    /**
     * @vcr ok_wellknown_and_jwks.yml
     */
    public function testJwtWithNoIssuer()
    {
        $badJwt = JWT::encode(['dummy' => 'data'], static::$privateKey, 'RS256');
        $this->assertSame(false, $this->BYUJWT->validateJWT($badJwt));
        $this->assertInstanceOf(
            'BYU\JWT\NoIssuerException',
            $this->BYUJWT->lastException
        );
    }

    /**
     * @vcr ok_wellknown_and_jwks.yml
     */
    public function testJwtWithWrongIssuer()
    {
        $badJwt = JWT::encode(
            ['iss' => 'bad', 'dummy' => 'data'],
            static::$privateKey,
            'RS256'
        );
        $this->assertSame(false, $this->BYUJWT->validateJWT($badJwt));
        $this->assertInstanceOf(
            'BYU\JWT\BadIssuerException',
            $this->BYUJWT->lastException
        );
    }

    /**
     * @vcr ok_wellknown_and_jwks.yml
     */
    public function testJwtWithNoExpiration()
    {
        $badJwt = JWT::encode(
            ['iss' => 'https://api.byu.edu', 'dummy' => 'data'],
            static::$privateKey,
            'RS256'
        );
        $this->assertSame(false, $this->BYUJWT->validateJWT($badJwt));
        $this->assertInstanceOf(
            'BYU\JWT\NoExpirationException',
            $this->BYUJWT->lastException
        );
    }

    /**
     * @vcr ok_wellknown_and_jwks.yml
     */
    public function testParsedClaims()
    {
        $json = '{
            "iss" : "https://api.byu.edu",
            "exp" : ' . (time() + 10) . ',
            "http://wso2.org/claims/subscriber" : "BYU/gds2",
            "http://wso2.org/claims/applicationid" : "2350",
            "http://wso2.org/claims/applicationname" : "dockerlocalhost",
            "http://wso2.org/claims/applicationtier" : "Unlimited",
            "http://wso2.org/claims/apicontext" : "/domains/byusa/clubs/v1",
            "http://wso2.org/claims/version" : "v1",
            "http://wso2.org/claims/tier" : "Unlimited",
            "http://wso2.org/claims/keytype" : "SANDBOX",
            "http://wso2.org/claims/usertype" : "APPLICATION_USER",
            "http://wso2.org/claims/enduser" : "tave@carbon.super",
            "http://wso2.org/claims/enduserTenantId" : "-1234",
            "http://byu.edu/claims/resourceowner_suffix" : " ",
            "http://byu.edu/claims/client_rest_of_name" : "Glen D",
            "http://byu.edu/claims/resourceowner_person_id" : "578205422",
            "http://byu.edu/claims/resourceowner_byu_id" : "268188640",
            "http://wso2.org/claims/client_id" : "PcnfjpwGZUjQVeItRzfWbY8AAw0a",
            "http://byu.edu/claims/resourceowner_net_id" : "tave",
            "http://byu.edu/claims/resourceowner_surname" : "Sawyer",
            "http://byu.edu/claims/client_person_id" : "420206942",
            "http://byu.edu/claims/client_sort_name" : "Sawyer, Glen D",
            "http://byu.edu/claims/client_claim_source" : "CLIENT_SUBSCRIBER",
            "http://byu.edu/claims/client_net_id" : "gds2",
            "http://byu.edu/claims/client_subscriber_net_id" : "gds2",
            "http://byu.edu/claims/resourceowner_prefix" : " ",
            "http://byu.edu/claims/resourceowner_surname_position" : "L",
            "http://byu.edu/claims/resourceowner_rest_of_name" : "Octavia Cathryn",
            "http://byu.edu/claims/client_name_suffix" : " ",
            "http://byu.edu/claims/client_surname" : "Sawyer",
            "http://byu.edu/claims/client_name_prefix" : " ",
            "http://byu.edu/claims/client_surname_position" : "L",
            "http://byu.edu/claims/resourceowner_preferred_first_name" : "Octavia",
            "http://byu.edu/claims/client_byu_id" : "617894086",
            "http://byu.edu/claims/client_preferred_first_name" : "Glen",
            "http://byu.edu/claims/resourceowner_sort_name" : "Sawyer, Octavia Cathryn"
        }';
        $data = json_decode($json);

        $jwt = JWT::encode($data, static::$privateKey, 'RS256');
        $decodedJwt = $this->BYUJWT->decode($jwt);

        $this->assertEquals("617894086", $decodedJwt['byu']['client']['byuId']);
        $this->assertEquals("CLIENT_SUBSCRIBER", $decodedJwt['byu']['client']['claimSource']);
        $this->assertEquals("gds2", $decodedJwt['byu']['client']['netId']);
        $this->assertEquals("420206942", $decodedJwt['byu']['client']['personId']);
        $this->assertEquals("Glen", $decodedJwt['byu']['client']['preferredFirstName']);
        $this->assertEquals(" ", $decodedJwt['byu']['client']['prefix']);
        $this->assertEquals("Glen D", $decodedJwt['byu']['client']['restOfName']);
        $this->assertEquals("Sawyer, Glen D", $decodedJwt['byu']['client']['sortName']);
        $this->assertEquals("gds2", $decodedJwt['byu']['client']['subscriberNetId']);
        $this->assertEquals(" ", $decodedJwt['byu']['client']['suffix']);
        $this->assertEquals("Sawyer", $decodedJwt['byu']['client']['surname']);
        $this->assertEquals("L", $decodedJwt['byu']['client']['surnamePosition']);
        $this->assertEquals("268188640", $decodedJwt['byu']['resourceOwner']['byuId']);
        $this->assertEquals("tave", $decodedJwt['byu']['resourceOwner']['netId']);
        $this->assertEquals("578205422", $decodedJwt['byu']['resourceOwner']['personId']);
        $this->assertEquals("Octavia", $decodedJwt['byu']['resourceOwner']['preferredFirstName']);
        $this->assertEquals(" ", $decodedJwt['byu']['resourceOwner']['prefix']);
        $this->assertEquals("Octavia Cathryn", $decodedJwt['byu']['resourceOwner']['restOfName']);
        $this->assertEquals("Sawyer, Octavia Cathryn", $decodedJwt['byu']['resourceOwner']['sortName']);
        $this->assertEquals(" ", $decodedJwt['byu']['resourceOwner']['suffix']);
        $this->assertEquals("Sawyer", $decodedJwt['byu']['resourceOwner']['surname']);
        $this->assertEquals("L", $decodedJwt['byu']['resourceOwner']['surnamePosition']);
        $this->assertEquals("268188640", $decodedJwt['byu']['webresCheck']['byuId']);
        $this->assertEquals("tave", $decodedJwt['byu']['webresCheck']['netId']);
        $this->assertEquals("578205422", $decodedJwt['byu']['webresCheck']['personId']);
        $this->assertEquals("/domains/byusa/clubs/v1", $decodedJwt['wso2']['apiContext']);
        $this->assertEquals("2350", $decodedJwt['wso2']['application']['id']);
        $this->assertEquals("dockerlocalhost", $decodedJwt['wso2']['application']['name']);
        $this->assertEquals("Unlimited", $decodedJwt['wso2']['application']['tier']);
        $this->assertEquals("PcnfjpwGZUjQVeItRzfWbY8AAw0a", $decodedJwt['wso2']['clientId']);
        $this->assertEquals("tave@carbon.super", $decodedJwt['wso2']['endUser']);
        $this->assertEquals("-1234", $decodedJwt['wso2']['endUserTenantId']);
        $this->assertEquals("SANDBOX", $decodedJwt['wso2']['keyType']);
        $this->assertEquals("BYU/gds2", $decodedJwt['wso2']['subscriber']);
        $this->assertEquals("Unlimited", $decodedJwt['wso2']['tier']);
        $this->assertEquals("APPLICATION_USER", $decodedJwt['wso2']['userType']);
        $this->assertEquals("v1", $decodedJwt['wso2']['version']);
    }

    /**
     * NOTE: no "@vcr" notation here, so this test is to actual live data
     */
    public function testRealWellKnown()
    {
        //one "live" test to https://api.byu.edu
        $this->assertNotEmpty((new BYUJWT)->getPublicKeys());
    }

    public function testJWTIssuer()
    {
        $issuer = $this->BYUJWT->getIssuer("x.y.z");
        $this->assertEmpty($issuer);

        $payload = base64_encode(json_encode(['iss' => 'Bob']));
        $issuer = $this->BYUJWT->getIssuer("x.${payload}.z");
        $this->assertEquals('Bob', $issuer);
    }

    /**
     * NOTE: Need to generate live tokens for the following two tests, so commenting out by default
     */

//    public function testTyk()
//    {
//        $foo = new BYUJWT(['wellKnownUrl' => 'https://api-sandbox.byu.edu/.well-known/openid-configuration']);
//        $decoded = $foo->decode("eyJraWQiOiJwdWJsaWM6YXBpLXNhbmRib3gtMSIsIng1dCI6IllsUmhnYzhNaW9tenNsRWlSOThPZmpDTFFQMCIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJodHRwczovL2FwaS5ieXUuZWR1IiwiZXhwIjoxNjU0MTEwNTExLCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL3N1YnNjcmliZXIiOiJCWVUvYnRtMjk2IiwiaHR0cDovL3dzbzIub3JnL2NsYWltcy9hcHBsaWNhdGlvbmlkIjoieXliYmpacUt0M0pvaHgzVU1lZUFhVTlNZnFRYSIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvYXBwbGljYXRpb25uYW1lIjoieXliYmpacUt0M0pvaHgzVU1lZUFhVTlNZnFRYSIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvYXBwbGljYXRpb250aWVyIjoiVW5saW1pdGVkIiwiaHR0cDovL3dzbzIub3JnL2NsYWltcy9hcGljb250ZXh0IjoiL2VjaG9jdXN0YXV0aC92MiIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvdmVyc2lvbiI6InYyIiwiaHR0cDovL3dzbzIub3JnL2NsYWltcy90aWVyIjoiVW5saW1pdGVkIiwiaHR0cDovL3dzbzIub3JnL2NsYWltcy9rZXl0eXBlIjoiU0FOREJPWCIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvdXNlcnR5cGUiOiJBUFBMSUNBVElPTl9VU0VSIiwiaHR0cDovL3dzbzIub3JnL2NsYWltcy9lbmR1c2VyIjoic214MDAwMDFAY2FyYm9uLnN1cGVyIiwiaHR0cDovL3dzbzIub3JnL2NsYWltcy9lbmR1c2VyVGVuYW50SWQiOiItMTIzNCIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvY2xpZW50X2lkIjoieXliYmpacUt0M0pvaHgzVU1lZUFhVTlNZnFRYSIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9jbGllbnRfc3Vic2NyaWJlcl9uZXRfaWQiOiJidG0yOTYiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X3BlcnNvbl9pZCI6IjcyMDIyMzE3MiIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9jbGllbnRfYnl1X2lkIjoiNzU4Mzc2MTYwIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL2NsaWVudF9uZXRfaWQiOiJidG0yOTYiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X3N1cm5hbWUiOiJNb3JnYW4iLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X3N1cm5hbWVfcG9zaXRpb24iOiJMIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL2NsaWVudF9yZXN0X29mX25hbWUiOiJCbGFrZSBUYW5uZXIiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X3ByZWZlcnJlZF9maXJzdF9uYW1lIjoiQmxha2UiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X3NvcnRfbmFtZSI6Ik1vcmdhbiwgQmxha2UgVGFubmVyIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL2NsaWVudF9uYW1lX3ByZWZpeCI6IiAiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X25hbWVfc3VmZml4IjoiICIsImh0dHA6Ly90eWsuaW8vY2xhaW1zL3VzZXJ0eXBlIjoiQVBQTElDQVRJT05fVVNFUiIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9yZXNvdXJjZW93bmVyX3BlcnNvbl9pZCI6Ijk2ODIxOTU4MiIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9yZXNvdXJjZW93bmVyX2J5dV9pZCI6IjMxMzE1MTA5MSIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9yZXNvdXJjZW93bmVyX25ldF9pZCI6InNteDAwMDAxIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL3Jlc291cmNlb3duZXJfc3VybmFtZSI6IlNteDAwMDAxIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL3Jlc291cmNlb3duZXJfc3VybmFtZV9wb3NpdGlvbiI6IkwiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvcmVzb3VyY2Vvd25lcl9yZXN0X29mX25hbWUiOiJTaXRlbWluZGVyIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL3Jlc291cmNlb3duZXJfcHJlZmVycmVkX2ZpcnN0X25hbWUiOiJTaXRlbWluZGVyIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL3Jlc291cmNlb3duZXJfc29ydF9uYW1lIjoiU214MDAwMDEsIFNpdGVtaW5kZXIiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvcmVzb3VyY2Vvd25lcl9wcmVmaXgiOiIgIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL3Jlc291cmNlb3duZXJfc3VmZml4IjoiICIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9jbGllbnRfY2xhaW1fc291cmNlIjoiQ0xJRU5UX1NVQlNDUklCRVIifQ.t_SSRMI5ld9KRvLBmIwN10ldGE5cRWrc1ke28Avlv3dVv_TuasqKzbsuRdNL-YXZCFdmDBaD8AFYFizq9dlvfXkdCkxobvkJ8SV5RWeVXooEnynPW8d8pV9e1C47eKCGdcjzJY8leA0rI890aEpwddu-iL-sHLOs6S-8yYl7aL_5lgcRZ57tsNdbaN9WXGGv4KP3CcJVdbj29l2CdawfD1vXQ4alMThAat3Q1or0dxN_JqgXLCIgOaQs6b5ZObNcOMeovEHuCVb7fpCFImq75EIU4RKZXU-Ehjg4TulSeZYLHUBv2D_deXH0gxN0T8DQcMLLbh5i6A7JTCIdSHOdqBeHVpZ47PIoO1PyMpk0jqgQisjdBqvqlbozVtzVsKpbBO4F1bW6y2kBf5cPCROzjs1Ku8SJU74qHDR-tO5zr8AKrekUCbx8rp7ACTshTExejf2-ET7h8nJtAex9FcQi3YbyfpaT085ziqOQzr5WibxYYMds6uVnYls9UbEV-UXHE38d6ZWjWTE-Smaq7p2RdHKi2DRSa8btr5Ckw4M3N7cFWEFEqy_OsMSgl99dKhu2UKuWNgqvWLfLcWe0dEnYHFyBNUDYUItVEyT64xAHc6Zw15hBCWNLs_14HLi8GxSeJIMNKCC-nA8x2J7prQcRrNdIGqsBz2-4bGfj-M1clS4");
//        $this->assertNotEmpty($decoded);
//    }
//
//    public function testLive()
//    {
//        $foo = new BYUJWT();
//        $decoded = $foo->decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlkySTVNemd4WWpZNVlUUXdNVGxqWkRVek4yWTJaamxqTURVNFpXWmpaVE14WmpWbU9USmxNZyJ9.eyJpc3MiOiJodHRwczovL2FwaS5ieXUuZWR1IiwiZXhwIjoxNjU0MTEwNzE2LCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL3N1YnNjcmliZXIiOiJCWVUvZ2RzMiIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvYXBwbGljYXRpb25pZCI6IjY0MSIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvYXBwbGljYXRpb25uYW1lIjoiRGVmYXVsdEFwcGxpY2F0aW9uIiwiaHR0cDovL3dzbzIub3JnL2NsYWltcy9hcHBsaWNhdGlvbnRpZXIiOiJVbmxpbWl0ZWQiLCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL2FwaWNvbnRleHQiOiIvZWNoby92MSIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvdmVyc2lvbiI6InYxIiwiaHR0cDovL3dzbzIub3JnL2NsYWltcy90aWVyIjoiU2lsdmVyIiwiaHR0cDovL3dzbzIub3JnL2NsYWltcy9rZXl0eXBlIjoiUFJPRFVDVElPTiIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvdXNlcnR5cGUiOiJBUFBMSUNBVElPTl9VU0VSIiwiaHR0cDovL3dzbzIub3JnL2NsYWltcy9lbmR1c2VyIjoiZ2RzMkBjYXJib24uc3VwZXIiLCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL2VuZHVzZXJUZW5hbnRJZCI6Ii0xMjM0IiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL3Jlc291cmNlb3duZXJfc3VmZml4IjoiICIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9jbGllbnRfcmVzdF9vZl9uYW1lIjoiR2xlbiBEYXZpZCIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9yZXNvdXJjZW93bmVyX3BlcnNvbl9pZCI6IjQyMDIwNjk0MiIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9yZXNvdXJjZW93bmVyX2J5dV9pZCI6IjYxNzg5NDA4NiIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvY2xpZW50X2lkIjoiNFpmODRhUk5JdUYzVTBKaTBydDhHdzR1ZnNBYSIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9yZXNvdXJjZW93bmVyX25ldF9pZCI6ImdkczIiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvcmVzb3VyY2Vvd25lcl9zdXJuYW1lIjoiU2F3eWVyIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL2NsaWVudF9wZXJzb25faWQiOiI0MjAyMDY5NDIiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X3NvcnRfbmFtZSI6IlNhd3llciwgR2xlbiBEYXZpZCIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9jbGllbnRfY2xhaW1fc291cmNlIjoiQ0xJRU5UX1NVQlNDUklCRVIiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X25ldF9pZCI6ImdkczIiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X3N1YnNjcmliZXJfbmV0X2lkIjoiZ2RzMiIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9yZXNvdXJjZW93bmVyX3ByZWZpeCI6IiAiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvcmVzb3VyY2Vvd25lcl9zdXJuYW1lX3Bvc2l0aW9uIjoiTCIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9yZXNvdXJjZW93bmVyX3Jlc3Rfb2ZfbmFtZSI6IkdsZW4gRGF2aWQiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X25hbWVfc3VmZml4IjoiICIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9jbGllbnRfc3VybmFtZSI6IlNhd3llciIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9jbGllbnRfbmFtZV9wcmVmaXgiOiIgIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL2NsaWVudF9zdXJuYW1lX3Bvc2l0aW9uIjoiTCIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9yZXNvdXJjZW93bmVyX3ByZWZlcnJlZF9maXJzdF9uYW1lIjoiR2xlbiIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9jbGllbnRfYnl1X2lkIjoiNjE3ODk0MDg2IiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL2NsaWVudF9wcmVmZXJyZWRfZmlyc3RfbmFtZSI6IkdsZW4iLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvcmVzb3VyY2Vvd25lcl9zb3J0X25hbWUiOiJTYXd5ZXIsIEdsZW4gRGF2aWQifQ.uqT2Vra-mfNYr5Xa6e3kyHwzxYjWwhXmoJ2roqWX6b0eb1SlTcjSMyWvAERwSYX1QgVS5UiI1mvc8RpRGcaNDJZLX97xs3HpRFeaL8yWRAsrqPAkwYpVcPRdE8eFmb-2rBo0ETQiXMasMUuL4e88eOilJeexh8rAdJoqb316AVEMsD5JYGhsrBboX8reHTRt7MxYr51hQ4LU1NP-mBZAOQ4F9WXbGT67b13ZiNihSklycZ_o_1vD4Na0uOMZ6NrhyhUfXCbEow2CyJdvHC7EbI_6BDvZZxl6j4lRgkyADge4CiuvP05FZTEaQoqCPenrynuKrzIDA2Ww6hXxkOQXcQ");
//        $this->assertNotEmpty($decoded);
//    }
}
