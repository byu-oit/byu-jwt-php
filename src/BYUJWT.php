<?php
// Copyright 2017 Brigham Young University
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

namespace BYU\JWT;

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
    public static $cacheWellKnowns = false;
    private static $_cache = [];
  
    $key = "example_key";
    $token = array(
        "iss" => "http://example.org",
        "aud" => "http://example.com",
        "iat" => 1356999524,
        "nbf" => 1357000000
    );

    /**
     * Get the response of the specified .well-known URL.
     * If cacheWellKnowns is set to true then it returns the previously retrieved response.
     *
     * @param string $wellKnownUrl
     *
     * @return object Parsed JSON response from the well known URL
     */
    public static function getWellKnown($wellKnownUrl)
    {
        if(static::$cacheWellKnowns && array_key_exists($wellKnownUrl, static::$_cache)) {
            return static::$_cache[$wellKnownUrl];
        }
        static::$_cache[$wellKnownUrl] = null;

        try {
            $client = new Client();
            $response = $client->get($wellKnownUrl);
        } catch (RequestException $e) {
            return null;
        }

        static::$_cache[$wellKnownUrl] = @json_decode($response->getBody());

        return static::$_cache[$wellKnownUrl];
    }

    public static function getPublicKey($wellKnownUrl)
    {
        //TODO
    }

    public static function verifyJWT($jwt, $wellKnownUrl)
    {
        //TODO
    }

    public static function jwtDecoded($jwt, $wellKnownUrl)
    {
      $jwt = JWT::encode($token, $key);
      $decoded = JWT::decode($jwt, $key, array('HS256'));
       
      /*
       NOTE: This will now be an object instead of an associative array. To get
       an associative array, you will need to cast it as such:
       */

       $decoded_array = (array) $decoded;
       return $decoded_array;
    }
}
