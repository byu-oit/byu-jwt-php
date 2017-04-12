# JWT Decoding and Validation for BYU API

Basic JWT Decoding and Validation for calls from BYU's API repository

# Requirements
* PHP 5.4+
* OpenSSL extension

## Installing via composer

Install into your project using [composer](http://getcomposer.org).
For existing applications you can add the
following to your composer.json file:

    "require": {
        "byu-oit/jwt": "~2.0"
    }

And run `php composer.phar update`

## Usage

The most common use case is simply decoding a JWT:
```php
try {
    $decoded = (new BYUJWT)->decode($jwt);
} catch (Exception $e) {
    //JWT was not valid, do something
}
```

The output is an array with the original JWT data, plus the standard BYU claims parsed out, e.g.
```php
[
	'iss' => 'https://api.byu.edu',
	'exp' => 1492013286,
	'http://wso2.org/claims/subscriber' => 'BYU/appnetid',
	'http://wso2.org/claims/applicationid' => '1234',
	'http://wso2.org/claims/applicationname' => 'DefaultApplication',
	'http://wso2.org/claims/applicationtier' => 'Unlimited',
	'http://wso2.org/claims/apicontext' => '/echo/v1',
	'http://wso2.org/claims/version' => 'v1',
	'http://wso2.org/claims/tier' => 'Unlimited',
	'http://wso2.org/claims/keytype' => 'SANDBOX',
	'http://wso2.org/claims/usertype' => 'APPLICATION_USER',
	'http://wso2.org/claims/enduser' => 'usernetid@carbon.super',
	'http://wso2.org/claims/enduserTenantId' => '-1234',
	'http://byu.edu/claims/resourceowner_suffix' => ' ',
	'http://byu.edu/claims/client_rest_of_name' => 'Appfirstname',
	'http://byu.edu/claims/resourceowner_person_id' => '123456789',
	'http://byu.edu/claims/resourceowner_byu_id' => '987654321',
	'http://wso2.org/claims/client_id' => 'XcnfjpwGZUjQVeItRzfWbY8AAw0a',
	'http://byu.edu/claims/resourceowner_net_id' => 'usernetid',
	'http://byu.edu/claims/resourceowner_surname' => 'Userlastname',
	'http://byu.edu/claims/client_person_id' => '111111111',
	'http://byu.edu/claims/client_sort_name' => 'Applastname, Appfirstname',
	'http://byu.edu/claims/client_claim_source' => 'CLIENT_SUBSCRIBER',
	'http://byu.edu/claims/client_net_id' => 'appnetid',
	'http://byu.edu/claims/client_subscriber_net_id' => 'appnetid',
	'http://byu.edu/claims/resourceowner_prefix' => ' ',
	'http://byu.edu/claims/resourceowner_surname_position' => 'L',
	'http://byu.edu/claims/resourceowner_rest_of_name' => 'Userfirstname',
	'http://byu.edu/claims/client_name_suffix' => ' ',
	'http://byu.edu/claims/client_surname' => 'Applastname',
	'http://byu.edu/claims/client_name_prefix' => ' ',
	'http://byu.edu/claims/client_surname_position' => 'L',
	'http://byu.edu/claims/resourceowner_preferred_first_name' => 'Userfirstname',
	'http://byu.edu/claims/client_byu_id' => '222222222',
	'http://byu.edu/claims/client_preferred_first_name' => 'Appfirstname',
	'http://byu.edu/claims/resourceowner_sort_name' => 'Userlastname, Userfirstname',
	'byu' => [
		'client' => [
			'byuId' => '222222222',
			'claimSource' => 'CLIENT_SUBSCRIBER',
			'netId' => 'appnetid',
			'personId' => '111111111',
			'preferredFirstName' => 'Appfirstname',
			'prefix' => ' ',
			'restOfName' => 'Appfirstname',
			'sortName' => 'Applastname, Appfirstname',
			'subscriberNetId' => 'appnetid',
			'suffix' => ' ',
			'surname' => 'Applastname',
			'surnamePosition' => 'L',
		],
		'resourceOwner' => [
			'byuId' => '987654321',
			'netId' => 'usernetid',
			'personId' => '123456789',
			'preferredFirstName' => 'Userfirstname',
			'prefix' => ' ',
			'restOfName' => 'Userfirstname',
			'sortName' => 'Userlastname, Userfirstname',
			'suffix' => ' ',
			'surname' => 'Userlastname',
			'surnamePosition' => 'L',
		],
		'webresCheck' => [
			'byuId' => '987654321',
			'netId' => 'usernetid',
			'personId' => '123456789',
		],
	],
	'wso2' => [
		'apiContext' => '/echo/v1',
		'application' => [
			'id' => '2350',
			'name' => 'DefaultApplication',
			'tier' => 'Unlimited',
		],
		'clientId' => 'XcnfjpwGZUjQVeItRzfWbY8AAw0a',
		'endUser' => 'usernetid@carbon.super',
		'endUserTenantId' => '-1234',
		'keyType' => 'SANDBOX',
		'subscriber' => 'BYU/appnetid',
		'tier' => 'Unlimited',
		'userType' => 'APPLICATION_USER',
		'version' => 'v1',
	],
]
```

Note that ```php $decoded['byu']['webresCheck'] ``` contains the identifiers for the 'resourceOwner' (i.e. the end user) if present, or the 'client' (i.e. the application owner) if not.
