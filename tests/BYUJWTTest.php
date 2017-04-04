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
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use PHPUnit\Framework\TestCase;

/**
 * @covers BYUJWT
 */
final class BYUJWTTest extends TestCase
{

    // Global valid jwt for use in tests against a valid JWT
    protected static $validJWT = "";
    // credentials used to generate valid JWT above
    protected static $credentials;

    /*
     * The test suite requires the wso2-test-credentials.json file to be present
     *
     * The location of the credentials can be modified using the WSO2_CRED_LOC env variable
     */
    public static function setUpBeforeClass() {
        // Set file location to WSO2_CRED_LOC if exists or to wso2-test-credentials.json
        $fileLocation = getenv("WSO2_CRED_LOC") ?: dirname(dirname(__FILE__)) . '/wso2-test-credentials.json';

        $credentialsJSON = file_get_contents($fileLocation);
        static::$credentials = json_decode($credentialsJSON);

        $client = new Client();
        try {
            $response = $client->post('https://api.byu.edu/token', [
                'body' => 'grant_type=client_credentials',
                'auth' => [static::$credentials->client_id, static::$credentials->client_secret]]);
        } catch (RequestException $e) {
            return null;
        }
        $token = json_decode($response->getBody());

        try {
            $echoResponse = $client->get('https://api.byu.edu/echo/v1/echo/hello', [
                'headers' => [
                    'Authorization' => "Bearer {$token->access_token}"]]);
        } catch (RequestException $e) {
            return null;
        }
        $echoBody = json_decode($echoResponse->getBody(), true);
        static::$validJWT = $echoBody['Headers']["X-Jwt-Assertion"][0];
    }

    public function setUp() {
        BYUJWT::reset();
        parent::setUp();
    }

    public function testModifyWellKnownHost()
    {
        $existingHost = BYUJWT::$wellKnownHost;
        $alternateWellKnownHost = "http://fake.com";
        BYUJWT::setWellKnownHost($alternateWellKnownHost);
        $this->assertEquals($alternateWellKnownHost, BYUJWT::$wellKnownHost);
        BYUJWT::setWellKnownHost($existingHost);
    }

    public function testGetPublicKey()
    {
        $key = BYUJWT::getPublicKey();
        $this->assertNotEmpty($key);
    }

    public function testGetWellKnown()
    {
        $wellKnown = BYUJWT::getWellKnown();
        $this->assertNotEmpty($wellKnown);
        $this->assertEquals($wellKnown->issuer, 'https://api.byu.edu');
    }

    public function testInvalidJWTReturnError()
    {
        //Using assertSame instead of assertEquals in this case, because
        //we want to ensure actual boolean "false" instead of "falsy" values
        //like void, null, 0, etc.
        $this->assertSame(false, BYUJWT::validateJWT("Blah blah this is not at all a valid JWT"));
        $this->assertInstanceOf('Exception', BYUJWT::$lastException);
    }

    public function testExpiredJWTReturnError()
    {
        // Expired JWT for a bot user
        $expiredJWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlpUUm1NMk5tWkRabFlUZG1aRFJqWVdJME1tTXpZamd4WWpNd1lXUXhNems0TnpFd09EVmxNdyJ9.eyJpc3MiOiJodHRwczovL2FwaS5ieXUuZWR1IiwiZXhwIjoxNDg5NzY4MTczLCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL3N1YnNjcmliZXIiOiJCWVUvYWRkZHJvcCIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvYXBwbGljYXRpb25pZCI6IjIwODUiLCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL2FwcGxpY2F0aW9ubmFtZSI6IkRlZmF1bHRBcHBsaWNhdGlvbiIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvYXBwbGljYXRpb250aWVyIjoiVW5saW1pdGVkIiwiaHR0cDovL3dzbzIub3JnL2NsYWltcy9hcGljb250ZXh0IjoiL2VjaG8vdjEiLCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL3ZlcnNpb24iOiJ2MSIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvdGllciI6IkJyb256ZSIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMva2V5dHlwZSI6IlBST0RVQ1RJT04iLCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL3VzZXJ0eXBlIjoiQVBQTElDQVRJT04iLCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL2VuZHVzZXIiOiJhZGRkcm9wQGNhcmJvbi5zdXBlciIsImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvZW5kdXNlclRlbmFudElkIjoiLTEyMzQiLCJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL2NsaWVudF9pZCI6IjVnekxqTVVjeDdxdXQzTXVTZjl4cjhHVjJCQWEiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X3Jlc3Rfb2ZfbmFtZSI6IkFkZCIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9jbGllbnRfcGVyc29uX2lkIjoiMzc3MjI4MDYyIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL2NsaWVudF9zb3J0X25hbWUiOiJEcm9wLCBBZGQiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X2NsYWltX3NvdXJjZSI6IkNMSUVOVF9TVUJTQ1JJQkVSIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL2NsaWVudF9uZXRfaWQiOiJhZGRkcm9wIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL2NsaWVudF9zdWJzY3JpYmVyX25ldF9pZCI6ImFkZGRyb3AiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X25hbWVfc3VmZml4IjoiICIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9jbGllbnRfc3VybmFtZSI6IkRyb3AiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X3N1cm5hbWVfcG9zaXRpb24iOiJMIiwiaHR0cDovL2J5dS5lZHUvY2xhaW1zL2NsaWVudF9uYW1lX3ByZWZpeCI6IiAiLCJodHRwOi8vYnl1LmVkdS9jbGFpbXMvY2xpZW50X2J5dV9pZCI6IjY0OTAxOTk2NSIsImh0dHA6Ly9ieXUuZWR1L2NsYWltcy9jbGllbnRfcHJlZmVycmVkX2ZpcnN0X25hbWUiOiJBZGQifQ.luAysmbldL0Hn1PO1TeHSba79tiVwnaEFLPMknsX5xegqExrJXs_FEge8R7PWj-KnjCMZt1QZbUeDz9boBWednXORSIHOk8TIZzM1hc3kM883sQXRbe9hiTfnoWf0zN2i9B6LBV1vqSFgJu7-PP_kAk0E1kfi7TcbWjecYc9H6vBijHrguh-WvwLuHg5qjC7en-FWcoYO_yM1oWvNajrUUdFbW6WC7lgkvnAPqreNlCuRA23uk45incuMNyFtldlMVOtAsqxRFgpydnujmnuP-l8gU2L1zFXdOkj-gTmq4v-sMCS2crrYW4MIVy5ObqlsQMOisjqturQLuxLo9fYpQ";

        $this->assertSame(false, BYUJWT::validateJWT($expiredJWT));
        $this->assertInstanceOf('Firebase\JWT\ExpiredException', BYUJWT::$lastException);
    }

    public function testJWTWithNoExpiration()
    {
        //Validation should be false when Expiration does not exist in an otherwise valid JWT
        $decoded = BYUJWT::decode(static::$validJWT);
        unset($decoded->exp);
        $badJwt = JWT::encode($decoded, BYUJWT::getPublicKey());

        $this->assertSame(false, BYUJWT::validateJWT($badJwt));
        $this->assertInstanceOf('BYU\JWT\NoExpirationException', BYUJWT::$lastException);
    }

    public function testHeaderConstants()
    {
        $this->assertEquals(BYUJWT::BYU_JWT_HEADER_CURRENT, "X-JWT-Assertion");
        $this->assertEquals(BYUJWT::BYU_JWT_HEADER_ORIGINAL, "X-JWT-Assertion-Original");
    }

    public function testJTWValidateSuccesful()
    {
        $this->assertSame(true, BYUJWT::validateJWT(static::$validJWT));
    }

    public function testJTWDecodeSuccesful()
    {
        $decodedJwt = BYUJWT::decode(static::$validJWT);
        $this->assertNotEmpty($decodedJwt);
        $this->assertEquals('https://api.byu.edu', $decodedJwt->iss);
        $this->assertEquals(static::$credentials->client_id, $decodedJwt->{'http://wso2.org/claims/client_id'});
    }
}
