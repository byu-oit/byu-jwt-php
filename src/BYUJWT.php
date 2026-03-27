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
use GuzzleHttp\Client;

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
    public function getWellKnown($issuer = "")
    {
        $cacheKey = 'wellKnown' . $issuer;
        $cached = $this->getCache($cacheKey);
        if (!empty($cached)) {
            return $cached;
        }

        $url = $this->wellKnownUrl;
        switch ($issuer) {
            case "https://api.byu.edu":
                $url = "https://api.byu.edu/.well-known/openid-configuration";
                break;
            case "https://api-sandbox.byu.edu":
                $url = "https://api-sandbox.byu.edu/.well-known/openid-configuration";
                break;
            case "https://api-dev.byu.edu":
                $url = "https://api-dev.byu.edu/.well-known/openid-configuration";
                break;
        }
        try {
            $response = $this->client->get($url);
        } catch (\Throwable $e) {
            $this->lastException = $e;
            return null;
        }

        $output = json_decode((string)$response->getBody());
        if (json_last_error() !== JSON_ERROR_NONE) {
            return null;
        }

        $this->setCache($cacheKey, $output);

        return $output;
    }

    /**
     * Get all public keys from the current well-known URL
     *
     * @return string[]
     */
    public function getPublicKeys($issuer = "")
    {
        $cacheKey = 'publicKeys' . $issuer;
        $cached = $this->getCache($cacheKey);
        if (!empty($cached)) {
            return $cached;
        }

        $keys = [];

        $wellKnown = $this->getWellKnown($issuer);
        if (empty($wellKnown->jwks_uri)) {
            return $keys;
        }

        try {
            $response = $this->client->get($wellKnown->jwks_uri);
        } catch (\Throwable $e) {
            $this->lastException = $e;
            return $keys;
        }

        $jwks = json_decode((string)$response->getBody(), true);
        if (!is_array($jwks)) {
            return $keys;
        }

        if (empty($jwks['keys']) || !is_array($jwks['keys'])) {
            return $keys;
        }

        foreach ($jwks['keys'] as $jwk) {
            if (!is_array($jwk)) {
                continue;
            }

            $key = $this->createPublicKeyFromJwk($jwk);
            if ($key !== null) {
                $keys[] = $key;
            }
        }

        if (!empty($keys)) {
            $this->setCache($cacheKey, $keys);
        }

        return $keys;
    }

    /**
     * Get the public key of the current well-known URL
     *
     * @return string
     */
    public function getPublicKey($issuer = "")
    {
        $cacheKey = 'publicKey' . $issuer;
        $cached = $this->getCache($cacheKey);
        if (!empty($cached)) {
            return $cached;
        }

        $keys = $this->getPublicKeys($issuer);
        if (empty($keys[0])) {
            return null;
        }

        $key = $keys[0];
        $this->setCache($cacheKey, $key);

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

    public function getIssuer($jwt)
    {
        $tks = \explode('.', $jwt);
        if (\count($tks) != 3) {
            return "";
        }
        $bodyb64 = $tks[1];
        $payloadJson = $this->base64UrlDecode($bodyb64);
        if ($payloadJson === null) {
            return "";
        }

        $payload = json_decode($payloadJson);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return "";
        }
        if (empty($payload->iss) || !is_string($payload->iss)) {
            return "";
        }

        return $payload->iss;
    }

    /**
     * Decode a JWT
     *
     * @param string $jwt JWT
     *
     * @return array decoded JWT
     *
     * @throws Exception Various exceptions for various problems with JWT
     *         (see Firebase\JWT\JWT::decode for details)
     */
    public function decode($jwt)
    {
        $parts = \explode('.', $jwt);
        if (\count($parts) !== 3) {
            throw new Exception('Could not decode JWT');
        }

        $headerJson = $this->base64UrlDecode($parts[0]);
        $payloadJson = $this->base64UrlDecode($parts[1]);
        $signature = $this->base64UrlDecode($parts[2]);
        if ($headerJson === null || $payloadJson === null || $signature === null) {
            throw new Exception('Could not decode JWT');
        }

        $header = json_decode($headerJson);
        $decodedObject = json_decode($payloadJson);
        if (
            json_last_error() !== JSON_ERROR_NONE ||
            !is_object($header) ||
            !is_object($decodedObject)
        ) {
            throw new Exception('Could not decode JWT');
        }

        $issuer = $this->getIssuer($jwt);
        $wellKnown = $this->getWellKnown($issuer);
        $keys = $this->getPublicKeys($issuer);
        if (
            empty($header->alg) ||
            !is_string($header->alg) ||
            !$this->isAlgorithmAllowed($header->alg, $wellKnown)
        ) {
            throw new Exception('Algorithm not allowed');
        }

        $signingInput = $parts[0] . '.' . $parts[1];
        $verified = false;
        foreach ($keys as $key) {
            $result = openssl_verify($signingInput, $signature, $key, OPENSSL_ALGO_SHA256);
            if ($result === 1) {
                $verified = true;
                break;
            }
        }

        if (!$verified) {
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
        if (!is_numeric($decodedObject->exp) || (int)$decodedObject->exp < time()) {
            throw new ExpiredException('Expired token');
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

    /**
     * Decode a base64url string into raw JSON.
     *
     * @param string $data Base64url-encoded payload
     *
     * @return string|null
     */
    protected function base64UrlDecode($data)
    {
        $remainder = strlen($data) % 4;
        if ($remainder !== 0) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            return null;
        }

        return $decoded;
    }

    /**
     * Convert a JWKS entry into a PEM-encoded RSA public key.
     *
     * @param array $jwk
     *
     * @return string|null
     */
    protected function createPublicKeyFromJwk(array $jwk)
    {
        if (!empty($jwk['x5c'][0]) && is_string($jwk['x5c'][0])) {
            return $this->createPublicKeyFromCertificate($jwk['x5c'][0]);
        }

        if (
            empty($jwk['kty']) ||
            $jwk['kty'] !== 'RSA' ||
            empty($jwk['n']) ||
            empty($jwk['e']) ||
            !is_string($jwk['n']) ||
            !is_string($jwk['e'])
        ) {
            return null;
        }

        $modulus = $this->base64UrlDecode($jwk['n']);
        $exponent = $this->base64UrlDecode($jwk['e']);
        if ($modulus === null || $exponent === null) {
            return null;
        }

        $rsaPublicKey = $this->asn1EncodeSequence(
            $this->asn1EncodeInteger($modulus)
            . $this->asn1EncodeInteger($exponent)
        );
        $algorithmIdentifier = hex2bin('300d06092a864886f70d0101010500');
        $subjectPublicKeyInfo = $this->asn1EncodeSequence(
            $algorithmIdentifier
            . $this->asn1EncodeBitString($rsaPublicKey)
        );

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    /**
     * Convert a DER certificate body into a PEM public key.
     *
     * @param string $certificateBody
     *
     * @return string|null
     */
    protected function createPublicKeyFromCertificate($certificateBody)
    {
        $certificate = "-----BEGIN CERTIFICATE-----\n"
            . chunk_split($certificateBody, 64, "\n")
            . "-----END CERTIFICATE-----\n";
        $publicKey = openssl_pkey_get_public($certificate);
        if ($publicKey === false) {
            return null;
        }

        $publicKeyDetails = openssl_pkey_get_details($publicKey);
        if ($publicKeyDetails === false || empty($publicKeyDetails['key'])) {
            return null;
        }

        return $publicKeyDetails['key'];
    }

    /**
     * Check the token algorithm against the well-known metadata.
     *
     * @param string $algorithm
     * @param object|null $wellKnown
     *
     * @return bool
     */
    protected function isAlgorithmAllowed($algorithm, $wellKnown)
    {
        if (
            empty($wellKnown) ||
            empty($wellKnown->id_token_signing_alg_values_supported) ||
            !is_array($wellKnown->id_token_signing_alg_values_supported)
        ) {
            return $algorithm === 'RS256';
        }

        return in_array($algorithm, $wellKnown->id_token_signing_alg_values_supported, true);
    }

    /**
     * ASN.1 DER-encode an INTEGER.
     *
     * @param string $value
     *
     * @return string
     */
    protected function asn1EncodeInteger($value)
    {
        if ($value === '') {
            $value = "\x00";
        }
        if (ord($value[0]) > 0x7f) {
            $value = "\x00" . $value;
        }

        return "\x02" . $this->asn1EncodeLength(strlen($value)) . $value;
    }

    /**
     * ASN.1 DER-encode a SEQUENCE.
     *
     * @param string $value
     *
     * @return string
     */
    protected function asn1EncodeSequence($value)
    {
        return "\x30" . $this->asn1EncodeLength(strlen($value)) . $value;
    }

    /**
     * ASN.1 DER-encode a BIT STRING.
     *
     * @param string $value
     *
     * @return string
     */
    protected function asn1EncodeBitString($value)
    {
        return "\x03" . $this->asn1EncodeLength(strlen($value) + 1) . "\x00" . $value;
    }

    /**
     * ASN.1 DER-encode a length.
     *
     * @param int $length
     *
     * @return string
     */
    protected function asn1EncodeLength($length)
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $encoded = '';
        while ($length > 0) {
            $encoded = chr($length & 0xff) . $encoded;
            $length >>= 8;
        }

        return chr(0x80 | strlen($encoded)) . $encoded;
    }
}
