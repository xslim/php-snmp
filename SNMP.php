<?php
/**
* Class for sending SNMP V2c traps.
*
* Usege:
*  
* $host = '192.168.1.1';
* $community = 'public';
*
* $vars[] = array('oid'=>'1.3.6.1.4.1.143.101.14.1.1.2.0', 'value'=>'message 1');
* $vars[] = array('oid'=>'1.3.6.1.4.1.143.101.14.1.1.2.1', 'value'=>'message 2'); 
*
* SNMP::trap($host, $vars, $community);
*
* @package  SNMP
* @version  0.2
* @author   Taras Kalapun <t.kalapun@gmail.com>    
*/

class SNMP {
  
  /**
  * Main function to send SNMP v2c traps
  *
  * @param  string $ip         IP address of trap demon.
  * @param  array  $varBinds   variable bindings.
  * @param  string $community  OPTIONAL Name of community to send traps to.
  * @return bool
  */
  public static function trap($ip, $varBinds=null, $community='public') 
  {   
    $data = self::prepareTrapPacket($varBinds, $community);
    
    if ($debug) dump($data);
    
    $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    socket_sendto($socket, $data, strlen($data), 0, $ip, 162);
    socket_close($socket);
    return true;
  }
  
  /*
  $varBinds = array('oid', 'value', opt 'type') // OID including count
  */
  protected static function prepareTrapPacket($varBinds=null, $community='public', $requestId=null) 
  {     
    $pSnmp['version']    = self::packVar(1); //pack('H*', '0201'.'01'); // version SNMP v2c
    $pSnmp['community']  = self::packVar($community);
    $pSnmp['type']       = pack('H*', 'a7'); // SNMPv2-Trap-PDU
    
    $requestId = ($requestId) ? $requestId : rand(10000, 30000); // from 10000 to 40000 ?
    $pSnmp['requestId']  = self::packVar($requestId);
    
    $pSnmp['errorStatus']  = self::packVar(0);
    $pSnmp['errorIndex']  = self::packVar(0);
    
    $upTime = rand(100, 900) * 1000000; //the time in milliseconds
    $pSnmp['sysUpTime']  = self::packVarBind(array('oid'   => '1.3.6.1.2.1.1.3.0', 
    'value' => $upTime, 
    'type'  => 'o' // x43
    ));
    
    $pSnmp['snmpTrapOID'] = self::packVarBind(array('oid'   => '1.3.6.1.6.3.1.1.4.1.0', 
    'value' => '1.3.6.1.2.1.31.2.1', 
    'type'  => 'oid'
    ));
    
    $pSnmp['varBinds']   = $pSnmp['sysUpTime'] 
    . $pSnmp['snmpTrapOID'] 
    . self::packVarBinds($varBinds);
    
    $pSnmp['varBindsHeader']  = pack('H*', '30' . self::hexlen($pSnmp['varBinds'],1));
    
    $pSnmp['body'] 		= $pSnmp['requestId']
    . $pSnmp['errorStatus']
    . $pSnmp['errorIndex']
    . $pSnmp['varBindsHeader'] 
    . $pSnmp['varBinds'];
    
    $pSnmp['bodyLen'] = pack('H*', self::hexlen($pSnmp['body'],1));
    
    $snmpPack 	  = $pSnmp['version'] 
    . $pSnmp['community'] 
    . $pSnmp['type']
    . $pSnmp['bodyLen'] 
    . $pSnmp['body'];
    
    $snmpPacket   = pack('H*', '30' . self::hexlen($snmpPack,1)) 
    . $snmpPack;
    
    return $snmpPacket;
  }
  
  protected static function packVarBinds($varBinds=null) 
  {
    $varPack = array();
    if ($varBinds) foreach ($varBinds as $var) $varPack[] = self::packVarBind($var);
    return implode('', $varPack);
  }
  
  /*
  $varBind = array('oid' , 'value')
  Description:
  beta oid packer
  oid count pass inside oid
  varBind = bindType + bindSize + oidType + oidSize + oid + valType + valSize + val
  */
  protected static function packVarBind($varBind) 
  {
    $varHead = self::packVar($varBind['oid'], 'oid');
    $varBody = self::packVar($varBind['value'], $varBind['type']);
    $varHB   = $varHead . $varBody;
    $varPackSize = strlen($varHead) + strlen($varBody);
    $varPack = pack('H*', '30' . self::hexlen($varHB)) . $varHB;
    return $varPack;
  }
  
  protected static function packVar($var, $type=null, $varInHex=false) 
  {  
  /**
    * @link http://en.wikipedia.org/wiki/Basic_encoding_rules
    P/C is the primitive/constructed bit, it specifies if the value is primitive like an INTEGER or constructed which means, it again holds TLV values like a SET. If the bit is "on" (value = 1), it indicates a constructed value.
    
    Name 						P/C 	dec	hex
    EOC (End-of-Content) 		P 		0 	0x00
    BOOLEAN 					P 		1 	0x01
    INTEGER 					P 		2 	0x02
    BIT STRING 					P/C 	3 	0x03
    OCTET STRING 				P/C 	4 	0x04
    NULL 						P 		5 	0x05
    OBJECT IDENTIFIER 			P 		6 	0x06
    Object Descriptor 			P 		7 	0x07
    EXTERNAL 					C 		8 	0x08
    REAL (float) 				P 		9 	0x09
    ENUMERATED 					P 		10 	0x0A
    EMBEDDED PDV 				C 		11 	0x0B
    UTF8String 					P/C 	12 	0x0C
    RELATIVE-OID 				P 		13 	0x0D
    SEQUENCE and SEQUENCE OF 	C 		16 	0x10
    SET and SET OF 				C 		17 	0x11
    NumericString 				P/C 	18 	0x12
    PrintableString 			P/C 	19 	0x13
    T61String 					P/C 	20 	0x14
    VideotexString 				P/C 	21 	0x15
    IA5String 					P/C 	22 	0x16
    UTCTime 					P/C 	23 	0x17
    GeneralizedTime 			P/C 	24 	0x18
    GraphicString 				P/C 	25 	0x19
    VisibleString 				P/C 	26 	0x1A
    GeneralString 				P/C 	27 	0x1B
    UniversalString 			P/C 	28 	0x1C
    CHARACTER STRING 			P/C 	29 	0x1D
    BMPString 					P/C 	30 	0x1E
    
    IpAddress						40
    Counter (Counter32 in SNMPv2)	41
    Gauge (Gauge32 in SNMPv 2)		42
    TimeTicks						43
    Opaque							44
    NsapAddress						45
    Counter64 (available only in SNMPv2)	46
    Uinteger32 (available only in SNMPv2)	47
    */
    $type2hex   = array( 's'=>'04', 'i'=>'02', 'oid'=>'06', 'o'=>'43');
    
    if ($type[0] == 'x') {
      $typeHex = $type[1] . $type[2];
      $type    = 'x';
    } else {
      $type       = ($type=='oid') ? $type : substr($type, 0, 1);
      $type       = ($type) ? $type : substr(gettype($var), 0, 1);
      $typeHex    = $type2hex[$type];
    }
    
    $varHex = '';
    if ($type == 'i')   $varHex = ($varInHex) ? $var : dec2hex($var); 
    if ($type == 's')   $varHex = ($varInHex) ? $var : str2hex($var);
    if ($type == 'o')   $varHex = ($varInHex) ? $var : dec2hex($var);
    if ($type == 'x')   $varHex = ($varInHex) ? $var : $var; // if object, we pass hex data in $var
    if ($type == 'oid') $varHex = ($varInHex) ? $var : oid2hex($var);
    
    $bodyPack = pack('H*', $varHex);
    $headPack = pack('H*', $typeHex . self::hexlen($bodyPack) );
    
    return $headPack . $bodyPack;
  }
  
  protected static function hexlen($s, $showPrefix=false) 
  {
    $len = strlen($s);
    $prefix = ($showPrefix) ? '81' : '';
    if ($len > 255)   $prefix = '82';
    if ($len > 65535) $prefix = '83';
    
    return $prefix . dec2hex($len);
  }
  
}

function str2hex($s) 
{
  $hex = '';
  for ($i=0;$i<strlen($s);$i++) $hex .= dec2hex(ord($s[$i]));
  return $hex;
}

function oid2hex($n) 
{
  if (is_int($n)) {
    $oidHex = ($n>127) ? dec2hex(128|$n/128) . dec2hex($n%128) : dec2hex($n);
  } else {
    $oidHex = '';
    $oid = explode('.', $n);
    $n1 = (40 * $oid[0]) + $oid[1];
    $oidHex .= dec2hex($n1);
    unset($oid[0], $oid[1]);
    foreach ($oid as $n) $oidHex .= oid2hex( (int)$n );
  }
  return $oidHex;
}

function dec2hex($n) 
{
  $n = dechex($n);
  if (strlen($n) & 1 == 1) $n = '0'.$n;
  return $n;
}

?>
