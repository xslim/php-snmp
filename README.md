# php-snmp
This class is for sending SNMP v2c traps from directly PHP, without using any command-line utilites or modules. Just socket_open and socket_sendto

Automatically exported from http://code.google.com/p/php-snmp

*NOTE:* Not maintained

## Usage

``` php
<?php

$host = '192.168.1.1';
$community = 'public';

$vars[] = array(
    'oid'    => '1.3.6.1.4.1.143.101.14.1.1.2.0',
    'value' => 'message 1'
    );
$vars[] = array(
    'oid'    => '1.3.6.1.4.1.143.101.14.1.1.2.1', 
    'value' => 'message 2',
    'type'   => 's'
    ); 

SNMP::trap($host, $vars, $community);
?>
```
