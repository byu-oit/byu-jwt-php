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

namespace BYU\JWT;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use phpseclib\File\X509;

/**
 * Provides helpful functions to retrieve a specified BYU
 * .well-known URL and verify BYU signed JWTs
 */
class BYUJWT
{
    protected $client;
    protected $cache = [];
    protected $wellKnownUrl;

    public $lastException;

    const BYU_JWT_HEADER_CURRENT = "X-JWT-Assertion";
    const BYU_JWT_HEADER_ORIGINAL = "X-JWT-Assertion-Original";

    /**
     * Default constructor
     *
     * @param type $settings Override default settings:
     *   - "wellKnownUrl" for well-known host
     *
     * @return void
     */
    public function __construct($settings = [])
    {
        $this->client = new Client();
        $this->wellKnownUrl = 'https://api.byu.edu/.well-known/openid-configuration';

        if (!empty($settings['wellKnownUrl'])) {
            $this->wellKnownUrl = $settings['wellKnownUrl'];
        }
    }

    /**
     * Get the response of the specified .well-known URL.
     *
     * @return object Parsed JSON response from the well known URL
     */
    public function getWellKnown()
    {
        $cached = $this->getCache('wellKnown');
        if (!empty($cached)) {
            return $cached;
        }

        try {
            $response = $this->client->get($this->wellKnownUrl);
        } catch (RequestException $e) {
            $this->lastException = $e;
            return null;
        }

        $output = json_decode($response->getBody());
        if (json_last_error() !== JSON_ERROR_NONE) {
            return null;
        }

        $this->setCache('wellKnown', $output);

        return $output;
    }

    /**
     * Get all public keys from the current well-known URL
     *
     * @return string[]
     */
    public function getPublicKeys()
    {
        $cached = $this->getCache('publicKeys');
        if (!empty($cached)) {
            return $cached;
        }

        $keys = [];

        $wellKnown = $this->getWellKnown();
        if (empty($wellKnown->jwks_uri)) {
            return $keys;
        }

        try {
            $response = $this->client->get($wellKnown->jwks_uri);
        } catch (RequestException $e) {
            $this->lastException = $e;
            return $keys;
        }

        $jwks = json_decode($response->getBody(), true);
        try {
            $keys = JWK::parseKeySet($jwks);
            $this->setCache('publicKeys', $keys);
        } catch (\Exception $e) {
            // Intentional ignore
        }

        return $keys;
    }

    /**
     * Get the public key of the current well-known URL
     *
     * @return string
     */
    public function getPublicKey()
    {
        $cached = $this->getCache('publicKey');
        if (!empty($cached)) {
            return $cached;
        }

        $wellKnown = $this->getWellKnown();
        if (empty($wellKnown->jwks_uri)) {
            return null;
        }

        try {
            $response = $this->client->get($wellKnown->jwks_uri);
        } catch (RequestException $e) {
            $this->lastException = $e;
            return null;
        }

        $jwks = json_decode($response->getBody());
        if (empty($jwks->keys[0]->x5c[0])) {
            return null;
        }

        $X509 = new X509();
        if (!$X509->loadX509($jwks->keys[0]->x5c[0])) {
            return null;
        }

        $key = (string)$X509->getPublicKey();

        $this->setCache('publicKey', $key);

        return $key;
    }

    /**
     * Check if a JWT is valid
     *
     * @param string $jwt JWT
     *
     * @return bool true if $jwt is a valid JWT, false if not
     */
    public function validateJWT($jwt)
    {
        try {
            $decoded = $this->decode($jwt);
            return !empty($decoded);
        } catch (Exception $e) {
            //For simple true/false validation we don't throw exceptions;
            //just return false but store exception in case further
            //details are wanted
            $this->lastException = $e;
            return false;
        }
    }

    /**
     * Decode a JWT
     *
     * @param string $jwt JWT
     *
     * @return object decoded JWT
     *
     * @throws Exception Various exceptions for various problems with JWT
     *         (see Firebase\JWT\JWT::decode for details)
     */
    public function decode($jwt)
    {
        $wellKnown = $this->getWellKnown();
        $keys = $this->getPublicKeys();
        foreach ($keys as $key) {
            try {
                $decodedObject = JWT::decode(
                    $jwt,
                    $key,
                    $wellKnown->id_token_signing_alg_values_supported
                );
                break; // Successful decode, so exit loop
            } catch (\Exception $decodeError) {

            }
        }

        if (empty($decodedObject)) {
            if (!empty($decodeError)) {
                throw $decodeError;
            }
            throw new Exception('Could not decode JWT');
        }
        //Firebase\JWT\JWT::decode does not verify that some required
        //fields actually exist
        if (empty($decodedObject->iss)) {
            throw new NoIssuerException('No issuer in JWT');
        }
        if ($decodedObject->iss != $wellKnown->issuer) {
            throw new BadIssuerException('JWT issuer does not match well-known');
        }
        if (empty($decodedObject->exp)) {
            //Firebase\JWT\JWT does throw an exception if 'exp' field is in
            //the past, but not if it's completely missing
            throw new NoExpirationException('No expiration in JWT');
        }

        //JWT::decode returns at stdClass object, but iterating through keys is much
        //simpler with an array. So here's a quick Object-to-Array conversion
        $decoded = json_decode(json_encode($decodedObject), true);

        return $this->parseClaims($decoded);
    }

    /**
     * Parse standard set of 'http://XXXX/claims/YYYY' claims and save as
     * hierarchal array data
     *
     * @param array $jwt
     *
     * @return array
     */
    public function parseClaims($jwt)
    {
        //PHP 7 has convenient "??" operator, but we're making this
        //5.4+ compatible. So this is a simple "safe array access" that
        //won't cause warnings or errors if we try to get a non-existent key
        $get = function ($arr, $key) {
            return array_key_exists($key, $arr) ? $arr[$key] : null;
        };

        $hasResourceOwner = array_key_exists('http://byu.edu/claims/resourceowner_byu_id', $jwt);

        $jwt['byu']['client'] = [
            'byuId' =>              $get($jwt, 'http://byu.edu/claims/client_byu_id'),
            'claimSource' =>        $get($jwt, 'http://byu.edu/claims/client_claim_source'),
            'netId' =>              $get($jwt, 'http://byu.edu/claims/client_net_id'),
            'personId' =>           $get($jwt, 'http://byu.edu/claims/client_person_id'),
            'preferredFirstName' => $get($jwt, 'http://byu.edu/claims/client_preferred_first_name'),
            'prefix' =>             $get($jwt, 'http://byu.edu/claims/client_name_prefix'),
            'restOfName' =>         $get($jwt, 'http://byu.edu/claims/client_rest_of_name'),
            'sortName' =>           $get($jwt, 'http://byu.edu/claims/client_sort_name'),
            'subscriberNetId' =>    $get($jwt, 'http://byu.edu/claims/client_subscriber_net_id'),
            'suffix' =>             $get($jwt, 'http://byu.edu/claims/client_name_prefix'),
            'surname' =>            $get($jwt, 'http://byu.edu/claims/client_surname'),
            'surnamePosition' =>    $get($jwt, 'http://byu.edu/claims/client_surname_position')
        ];

        if ($hasResourceOwner) {
            $jwt['byu']['resourceOwner'] = [
                'byuId' =>              $get($jwt, 'http://byu.edu/claims/resourceowner_byu_id'),
                'netId' =>              $get($jwt, 'http://byu.edu/claims/resourceowner_net_id'),
                'personId' =>           $get($jwt, 'http://byu.edu/claims/resourceowner_person_id'),
                'preferredFirstName' => $get($jwt, 'http://byu.edu/claims/resourceowner_preferred_first_name'),
                'prefix' =>             $get($jwt, 'http://byu.edu/claims/resourceowner_prefix'),
                'restOfName' =>         $get($jwt, 'http://byu.edu/claims/resourceowner_rest_of_name'),
                'sortName' =>           $get($jwt, 'http://byu.edu/claims/resourceowner_sort_name'),
                'suffix' =>             $get($jwt, 'http://byu.edu/claims/resourceowner_suffix'),
                'surname' =>            $get($jwt, 'http://byu.edu/claims/resourceowner_surname'),
                'surnamePosition' =>    $get($jwt, 'http://byu.edu/claims/resourceowner_surname_position')
            ];
        }

        $webresCheckKey = $hasResourceOwner ? 'resourceOwner' : 'client';
        $jwt['byu']['webresCheck'] = [
            'byuId' => $jwt['byu'][$webresCheckKey]['byuId'],
            'netId' => $jwt['byu'][$webresCheckKey]['netId'],
            'personId' => $jwt['byu'][$webresCheckKey]['personId']
        ];

        $jwt['wso2'] = [
            'apiContext' =>         $get($jwt, 'http://wso2.org/claims/apicontext'),
            'application' => [
                'id' =>             $get($jwt, 'http://wso2.org/claims/applicationid'),
                'name' =>           $get($jwt, 'http://wso2.org/claims/applicationname'),
                'tier' =>           $get($jwt, 'http://wso2.org/claims/applicationtier')
            ],
            'clientId' =>           $get($jwt, 'http://wso2.org/claims/client_id'),
            'endUser' =>            $get($jwt, 'http://wso2.org/claims/enduser'),
            'endUserTenantId' =>    $get($jwt, 'http://wso2.org/claims/enduserTenantId'),
            'keyType' =>            $get($jwt, 'http://wso2.org/claims/keytype'),
            'subscriber' =>         $get($jwt, 'http://wso2.org/claims/subscriber'),
            'tier' =>               $get($jwt, 'http://wso2.org/claims/tier'),
            'userType' =>           $get($jwt, 'http://wso2.org/claims/usertype'),
            'version' =>            $get($jwt, 'http://wso2.org/claims/version')
        ];

        return $jwt;
    }

    /**
     * Simple cache reader. Implemented as a function so that if you don't
     * want caching, you can make a subclass that overrides this
     * function and always returns false
     *
     * @param string $key Cache key
     *
     * @return various
     */
    protected function getCache($key)
    {
        if (array_key_exists($key, $this->cache)) {
            return $this->cache[$key];
        }
        return false;
    }

    /**
     * Simple cache setter. See comment for "getCache" above.
     *
     * @param string  $key   Cache key
     * @param various $value Cache value
     *
     * @return void
     */
    protected function setCache($key, $value)
    {
        $this->cache[$key] = $value;
    }
}
