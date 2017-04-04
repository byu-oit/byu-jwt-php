# JWT Decoding and Validation for BYU API

Basic JWT Decoding and Validation for calls from BYU's API repository

## Installing via composer

Install into your project using [composer](http://getcomposer.org).
For existing applications you can add the
following to your composer.json file:

    "require": {
        "byu-oit/jwt": "~1.0"
    }

And run `php composer.phar update`

## Usage

The most common use case is simply decoding a JWT:
```php
try {
    $decoded = BYUJWT::decode($jwt);
} catch (Exception $e) {
    //JWT was not valid, do something
}
```
