<?php
namespace BYU\JWT;

//use Firebase\JWT\JWT as FireJWT; //used in "verify" function
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
        //TODO
    }
}