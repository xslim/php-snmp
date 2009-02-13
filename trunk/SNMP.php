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
        $trap['version']    = self::packVar(1); //pack('H*', '0201'.'01'); // version SNMP v2c
        $trap['community']  = self::packVar($community);
		
		$requestId = ($requestId) ? $requestId : rand(10000, 30000); // from 10000 to 40000 ?
		$trap['header']     = self::packVar($requestId) // requestId
							. self::packVar(0)			 // errorStatus
							. self::packVar(0);		 // errorIndex
		
		$upTime = rand(100, 900) * 1000000;
        $trap['sysUpTime']  = self::packVarBind(array('oid'   => '1.3.6.1.2.1.1.3.0', 
                                                       'value' => $upTime, 
                                                       'type'  => 'o' // x43
                                                      ));
                                                
        $trap['snmpTrapOID'] = self::packVarBind(array('oid'   => '1.3.6.1.6.3.1.1.4.1.0', 
                                                       'value' => '1.3.6.1.2.1.31.2.1', 
                                                       'type'  => 'oid'
                                                      ));
        
        $trap['varBinds']   = $trap['sysUpTime'] 
						 	. $trap['snmpTrapOID'] 
						 	. self::packVarBinds($varBinds);
        
        $trap['varBindsHeader']  = pack('H*', '30' . self::hexlen($trap['varBinds'],1));
        
        $trap['body'] 		= $trap['header'] 
							. $trap['varBindsHeader'] 
							. $trap['varBinds'];
        
        $trap['head'] = pack('H*', 'a7'. self::hexlen($trap['body'],1));
        
        $trapPack 	  = $trap['version'] 
					  . $trap['community'] 
					  . $trap['head'] 
					  . $trap['body'];
					
        $trapPacket   = pack('H*', '30' . self::hexlen($trapPack,1)) 
					  . $trapPack;
					
        return $trapPacket;
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
        /*
            x04 - string
            x06 - OID
            x30 - varBind start
            x02 - int
            x43 - object ?
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
        if ($type == 'i')   $varHex = ($varInHex) ? $var : self::dec2hex($var); 
        if ($type == 's')   $varHex = ($varInHex) ? $var : self::str2hex($var);
        if ($type == 'o')   $varHex = ($varInHex) ? $var : self::dec2hex($var);
        if ($type == 'x')   $varHex = ($varInHex) ? $var : $var; // if object, we pass hex data in $var
        if ($type == 'oid') $varHex = ($varInHex) ? $var : self::oid2hex($var);
        
        $bodyPack = pack('H*', $varHex);
        $headPack = pack('H*', $typeHex . self::hexlen($bodyPack) );
        
        return $headPack . $bodyPack;
    }
    
    protected static function str2hex($s) 
	{
        $hex = '';
        for ($i=0;$i<strlen($s);$i++) $hex .= self::dec2hex(ord($s[$i]));
        return $hex;
    }
    
    protected static function dec2hex($i) 
	{
        $i = dechex($i);
        if (strlen($i) & 1 == 1) $i = '0'.$i;
        return $i;
    }
    
    protected static function oid2hex($oid) 
	{
        $oidHex = '';
        if (substr($oid, 0, 3) == '1.3') {
            $oidHex .= '2b';
            $oid = substr($oid, 3);
        }
        $oid = trim($oid, '.');
        $oid = explode('.', $oid);
        foreach ($oid as $n) $oidHex .= self::dec2hex($n);

        return $oidHex;
    }
    
	protected static function hexlen($s, $showPrefix=false) 
	{
        $len = strlen($s);
        $prefix = ($showPrefix) ? '81' : '';
        if ($len > 255)   $prefix = '82';
        if ($len > 65535) $prefix = '83';
        
        return $prefix . self::dec2hex($len);
    }

}
