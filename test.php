<?

//echo base_convert(2680, 10, 128);
echo oid2hex('1.3.1981');
echo "<br>";
echo 128 | 2680/128;

function getNumericStringIndex($string_idx) {
     $string_idx = substr($string_idx, 1, strlen($string_idx)-2);
     $ret = strlen($string_idx);
     for ($i=0; $i<strlen($string_idx); $i++)
        $ret .= '.'.ord($string_idx[$i]);

     return $ret;
}

/**
 * Urban: This is the old function which fails for large numbers in the OID
 * Use SNMP::oid2hex instead which is "borrowed" :) from phpseclib (full credit)
 */
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

/*
	
static void MakeBase128( unsigned long l, int first ){
	if( l > 127 )	{		MakeBase128( l / 128, 0 );	}
	l %= 128;
	if( first )	{		abBinary[nBinary++] = (unsigned char)l;	}
	else	{		abBinary[nBinary++] = 0x80 | (unsigned char)l;	}
}
*/
	
?>