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
use phpseclib\File\X509;

/**
 * Provides helpful functions to retrieve a specified BYU .well-known URL and verify BYU signed JWTs
 *
 * @property boolean $cacheWellKnowns Can be set to enable or disable caching of the responses from well known URLs
 */
class BYUJWT
{
    public static $wellKnownHost = 'https://api.byu.edu';
    public static $useCache = true;
    public static $lastException;
    protected static $_cache = [];
    protected static $_client;

    const BYU_JWT_HEADER_CURRENT = "X-JWT-Assertion";
    const BYU_JWT_HEADER_ORIGINAL = "X-JWT-Assertion-Original";

    /**
     * Clear cache, reset variables
     *
     * @return void
     */
    public static function reset()
    {
        static::$wellKnownHost = 'https://api.byu.edu';
        static::$useCache = true;
        static::$lastException = null;
        static::$_cache = [];
    }

    /**
     * Get the response of the specified .well-known URL.
     * If cacheWellKnowns is set to true then it returns the previously retrieved response.
     *
     * @return object Parsed JSON response from the well known URL
     */
    public static function getWellKnown()
    {
        if(static::$useCache) {
            if (array_key_exists(static::$wellKnownHost, static::$_cache) && array_key_exists('well-known', static::$_cache[static::$wellKnownHost])) {
                return static::$_cache[static::$wellKnownHost]['well-known'];
            }
            static::$_cache[static::$wellKnownHost]['well-known'] = null;
        }

        try {
            $response = static::client()->get(trim(static::$wellKnownHost, '/') . '/.well-known/openid-configuration');
        } catch (RequestException $e) {
            static::$lastException = $e;
            return null;
        }

        $output = json_decode($response->getBody());
        if (json_last_error() !== JSON_ERROR_NONE) {
            return null;
        }

        if (static::$useCache) {
            static::$_cache[static::$wellKnownHost]['well-known'] = $output;
        }

        return $output;
    }

    /**
     * Override the base "well known URL"
     *
     * @return void
     */
    public static function setWellKnownHost($host)
    {
        static::$wellKnownHost = $host;
    }

    /**
     * Get the public key of the current well-known URL
     *
     * @return string
     */
    public static function getPublicKey()
    {
        if(static::$useCache) {
            if (array_key_exists(static::$wellKnownHost, static::$_cache) && array_key_exists('public-key', static::$_cache[static::$wellKnownHost])) {
                return static::$_cache[static::$wellKnownHost]['public-key'];
            }
            static::$_cache[static::$wellKnownHost]['public-key'] = null;
        }

        $wellKnown = static::getWellKnown();
        if (empty($wellKnown->jwks_uri)) {
            return null;
        }

        try {
            $response = static::client()->get($wellKnown->jwks_uri);
        } catch (RequestException $e) {
            static::$lastException = $e;
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
        if (static::$useCache) {
            static::$_cache[static::$wellKnownHost]['public-key'] = $key;
        }
        return $key;
    }

    /**
     * Check if a JWT is valid
     *
     * @param string JWT
     *
     * @return boolean true if $jwt is a valid JWT, false if not
     */
    public static function validateJWT($jwt)
    {
        try {
            $decoded = static::decode($jwt);
            return !empty($decoded);
        } catch (Exception $e) {
            //For simple true/false validation we don't throw exceptions; just return false
            //but store exception in case further details are wanted
            static::$lastException = $e;
            return false;
        }
    }

    /**
     * Decode a JWT
     *
     * @param string JWT
     *
     * @return object decoded JWT
     *
     * @throws Exception Various exceptions for various problems with JWT (see Firebase\JWT\JWT::decode for details)
     */
    public static function decode($jwt)
    {
        $key = static::getPublicKey();
        $decoded = JWT::decode($jwt, $key, ['HS256','RS256','HS512','HS384']);
        if (empty($decoded->exp)) {
            //Firebase\JWT\JWT::decode does not throw an error if "exp" does not exist,
            //although it does throw an error if it exists but has already passed
            //For BYU we want to ensure that it does exist, as well as being valid
            throw new NoExpirationException('No expiration in JWT');
        }
        return $decoded;
    }

    protected static function client()
    {
        if (empty(static::$_client)) {
            static::$_client = new Client();
        }
        return static::$_client;
    }
}
