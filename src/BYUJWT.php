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
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

/**
 * Provides helpful functions to retrieve a specified BYU .well-known URL and verify BYU signed JWTs
 *
 * @property boolean $cacheWellKnowns Can be set to enable or disable caching of the responses from well known URLs
 */
class BYUJWT
{
    protected $wellKnownHost;
    protected $client;
    protected $cache = [];

    public $lastException;

    const BYU_JWT_HEADER_CURRENT = "X-JWT-Assertion";
    const BYU_JWT_HEADER_ORIGINAL = "X-JWT-Assertion-Original";

    /**
     * Default constructor
     *
     * @param type $settings Override default settings:
     *   - "host" for well-known host
     *   - "client" to override HttpClient for testing purposes
     *
     * @return void
     */
    public function __construct($settings = [])
    {
        $this->wellKnownHost = empty($settings['host']) ? 'https://api.byu.edu' : $settings['host'];
        $this->client = empty($settings['client']) ? new Client() : $settings['client'];
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
            $response = $this->client->get(trim($this->wellKnownHost, '/') . '/.well-known/openid-configuration');
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

        $keyResource = openssl_pkey_get_public("-----BEGIN CERTIFICATE-----\n{$jwks->keys[0]->x5c[0]}\n-----END CERTIFICATE-----");
        if (!$keyResource) {
            return null;
        }
        $key = openssl_pkey_get_details($keyResource)['key'];

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
            //For simple true/false validation we don't throw exceptions; just return false
            //but store exception in case further details are wanted
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
     * @throws Exception Various exceptions for various problems with JWT (see Firebase\JWT\JWT::decode for details)
     */
    public function decode($jwt)
    {
        $wellKnown = $this->getWellKnown();
        $key = $this->getPublicKey();
        $decodedObject = JWT::decode($jwt, $key, $wellKnown->id_token_signing_alg_values_supported);

        //JWT::decode returns at stdClass object, but iterating through keys is much
        //simpler with an array. So here's a quick Object-to-Array conversion
        $decoded = json_decode(json_encode($decodedObject), true);

        if (empty($decoded['exp'])) {
            //Firebase\JWT\JWT::decode does not throw an error if "exp" does not exist,
            //although it does throw an error if it exists but has already passed
            //For BYU we want to ensure that it does exist, as well as being valid
            throw new NoExpirationException('No expiration in JWT');
        }

        return $decoded;
    }

    /**
     * Simple cache reader. Implemented as a function so that if you don't
     * want caching, you can make a subclass that overrides this
     * function and always returns false
     *
     * @param string $key
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
     * @param string $key
     * @param various $value
     *
     * @return void
     */
    protected function setCache($key, $value)
    {
        $this->cache[$key] = $value;
    }
}
