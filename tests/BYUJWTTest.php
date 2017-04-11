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
use GuzzleHttp\Message\Response;
use GuzzleHttp\Stream\Stream;
use GuzzleHttp\Subscriber\Mock;
use PHPUnit\Framework\TestCase;

/**
 * @covers \BYU\JWT\BYUJWT
 */
final class BYUJWTTest extends TestCase
{

    protected static $openid;
    protected static $jwks;
    protected static $privateKey;

    public static function setUpBeforeClass()
    {
        static::$jwks = file_get_contents(dirname(__FILE__) . '/jwks.json');
        static::$openid = file_get_contents(dirname(__FILE__) . '/openid.json');

        $keyData = file_get_contents(dirname(__FILE__) . '/testing.key');
        static::$privateKey = openssl_pkey_get_private($keyData);
    }

    public function setUp()
    {
        $client = $this->mockClient([static::$openid, static::$jwks]);

        $this->BYUJWT = new BYUJWT(['client' => $client]);

        parent::setUp();
    }

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

    public function testJwtValidate()
    {
        $jwt = JWT::encode(
            ['iss' => 'https://api.byu.edu', 'exp' => time() + 10],
            static::$privateKey, 'RS256'
        );
        $this->assertSame(true, $this->BYUJWT->validateJWT($jwt));
    }

    public function testWellKnown()
    {
        $wellKnown = $this->BYUJWT->getWellKnown();
        $this->assertNotEmpty($wellKnown);
        $this->assertEquals($wellKnown->issuer, 'https://api.byu.edu');
    }

    public function testPublicKey()
    {
        $key = $this->BYUJWT->getPublicKey();
        $this->assertNotEmpty($key);
        $cachedKey = $this->BYUJWT->getPublicKey();
        $this->assertEquals($key, $cachedKey);
    }

    public function testMissingWellKnown()
    {
        $client = $this->mockClient();
        $BYUJWT = new BYUJWT(['client' => $client]);

        $this->assertEmpty($BYUJWT->getWellKnown());
        $this->assertEmpty($BYUJWT->getPublicKey());
    }

    public function testBadWellKnown()
    {
        $client = $this->mockClient(['bad JSON!}}}']);
        $BYUJWT = new BYUJWT(['client' => $client]);

        $this->assertEmpty($BYUJWT->getWellKnown());
    }

    public function testMissingJwks()
    {
        $client = $this->mockClient([static::$openid]);
        $BYUJWT = new BYUJWT(['client' => $client]);

        $this->assertNotEmpty($BYUJWT->getWellKnown());
        $this->assertEmpty($BYUJWT->getPublicKey());
    }

    public function testBadJwks()
    {
        $client = $this->mockClient([static::$openid, 'bad JSON!}}}']);
        $BYUJWT = new BYUJWT(['client' => $client]);

        $this->assertNotEmpty($BYUJWT->getWellKnown());
        $this->assertEmpty($BYUJWT->getPublicKey());
    }

    public function testBadJwksKey()
    {
        $badKey = ['keys' => [['x5c' => ['bad RSA key!']]]];
        $client = $this->mockClient([static::$openid, json_encode($badKey)]);
        $BYUJWT = new BYUJWT(['client' => $client]);

        $this->assertNotEmpty($BYUJWT->getWellKnown());
        $this->assertEmpty($BYUJWT->getPublicKey());
    }

    public function testInvalidJWT()
    {
        //Using assertSame instead of assertEquals in this case, because
        //we want to ensure actual boolean "false" instead of "falsy" values
        //like void, null, 0, etc.
        $this->assertSame(false, $this->BYUJWT->validateJWT("bad JWT!"));
        $this->assertInstanceOf('Exception', $this->BYUJWT->lastException);
    }

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

    public function testJwtWithNoIssuer()
    {
        $badJwt = JWT::encode(['dummy' => 'data'], static::$privateKey, 'RS256');
        $this->assertSame(false, $this->BYUJWT->validateJWT($badJwt));
        $this->assertInstanceOf(
            'BYU\JWT\NoIssuerException',
            $this->BYUJWT->lastException
        );
    }

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

    public function testRealWellKnown()
    {
        //one "live" test to https://api.byu.edu
        $this->assertNotEmpty((new BYUJWT)->getWellKnown());
    }

    protected function mockClient($responseTexts = [])
    {
        $responses = [];
        foreach ($responseTexts as $text) {
            $body = Stream::factory($text);
            $responses[] = new Response(200, [], $body);
        }

        $mock = new Mock($responses);

        $client = new Client();
        $client->getEmitter()->attach($mock);

        return $client;
    }
}
