<?php

/**
    cmu.php is a thin PHP scripting layer on top of the SafeNet cmu (Certificate Management Utility)

    Given a slot number and a pin from the environment vars: CMU_SLOT and CMU_PIN it allows you to:

    list objects            cmu::listobjects
    import existing keys    cmu::importkey
    filter objects by label cmu::filterbylabel
    generate keys           cmu::genkey
    delete keys             cmu::delkey
    selfsign certs          cmu::selfsign
    export certs in pem     cmu::exportpem

    It expects the expect utility to be installed

*/

cmu::$pin  = getenv('CMU_PIN');
cmu::$slot = getenv('CMU_SLOT');

cmu::pp(cmu::listobjects(cmu::$slot, cmu::$pin));


cmu::pp(cmu::listobjects(cmu::$slot, cmu::$pin));

//print_r(cmu::getattributes(cmu::$slot, cmu::$pin, $handles));

//cmu::importkey(cmu::$slot, cmu::$pin, 'wayf.wayf.dk.key');
//$handles = cmu::filterbylabel(cmu::$slot, cmu::$pin, '/^CMU Unwrapped RSA Private Key$/');
//cmu::setattributes(cmu::$slot, cmu::$pin, $handles[0]['handle'], array('-label' => 'wayf.wayf.dk.key'));

//cmu::importkey(cmu::$slot, cmu::$pin, '/etc/ssl/wayf/private/wildcard.wayf.dk.3.key');
//cmu::setattributes(cmu::$slot, cmu::$pin, $objs[0]['handle'], array('-label' => 'wildcard.wayf.dk.key'));
//cmu::genkey(cmu::$slot, cmu::$pin, 'nemlogin.wayf.dk');
//cmu::delkey(cmu::$slot, cmu::$pin, $handles);
//$handles = cmu::filterbylabel(cmu::$slot, cmu::$pin, '/^32cc4606bc6c76b7dba95626531f8c46899bc944.key$/');

//foreach(range(1001, 1001) as $x) { print cmu::genkey(cmu::$slot, cmu::$pin, 'birk.wayf.dk-' . $x); }
//foreach(range(15, 122) as $handle) {  cmu::delkey(cmu::$slot, cmu::$pin, $handle); }
//foreach(range(1, 10) as $x) { cmu::selfsign(cmu::$slot, cmu::$pin, 'birk.wayf.dk-' . $x, 28, 'birk.wayf.dk-' . $x ,  $x); }
//foreach(range(32, 39) as $handle) { cmu::exportpem(cmu::$slot, cmu::$pin, $handle); }
//print_r(cmu::getattributes(cmu::$slot, cmu::$pin, $handles));

// foreach(range(1, 250, 10) as $base) {
//     foreach(range($base, $base + 9) as $x) { cmu::selfsign(cmu::$slot, cmu::$pin, 'birk.wayf.dk-' . $x, 28, 'birk.wayf.dk-' . $x ,  $x); }
//     $handles = cmu::filterbylabel(cmu::$slot, cmu::$pin,  '/\.crt$/');
//     cmu::exportpem(cmu::$slot, cmu::$pin, $handles);
//     cmu::delkey(cmu::$slot, cmu::$pin, $handles);
// }


class cmu {

static $pin;
static $slot;

function pp($list)
{
    $list = cmu::getattributes(cmu::$slot, cmu::$pin, $list);
    foreach($list as $line) {
        $keyname = sha1('Modulus=' . strtoupper(trim($line['modulus'])) . "\n") . '.key';
        printf("%-6s%-45s%-25s\n", $line['handle'], $line['label'], $keyname);
    }
    print "\n";
}

function filterbylabel($slot, $pin, $labelpattern)
{
    $objects = array();
    $handles = cmu::listobjects($slot, $pin);
    foreach($handles as $handle => $obj) {
        if (preg_match($labelpattern, $obj['label'])) {
            $objects[] = $obj;
        }
    }
    return $objects;
}

function listobjects($slot, $pin)
{
    // the sleep is from  http://stackoverflow.com/questions/24412582 - makes the $pin not echo ???
    $cmd = <<<eof
/usr/bin/expect -c "
spawn -noecho /usr/safenet/lunaclient/bin/cmu list -slot=$slot
expect slot { sleep .001; send $pin\\n }
expect eof
exit
"
eof;
    $list = shell_exec($cmd);

    $objects = array();
    foreach(explode("\n", $list) as $line) {
        if (preg_match('/^handle=(\d+)\s+label=(.*)$/', trim($line), $d)) {
            list($dummy, $handle, $label) = $d;
            $objects[$handle] = array('handle' => $handle, 'label' => $label);
        }
    }

    return $objects;
}

function getattributes($slot, $pin, $handles)
{
    $objects = array();
    foreach($handles as $i => $handle) {
        $theobject = self::getattribute($slot, $pin, $handle['handle']);
        $theobject['handle'] = $handle['handle'];
        $objects[] = $theobject;
    }
    return $objects;
}

function getattribute($slot, $pin, $handle)
{
    $cmd = <<<eof
/usr/bin/expect -c "
spawn -noecho /usr/safenet/lunaclient/bin/cmu getattribute -slot=$slot -handle=$handle
expect slot { sleep .001; send $pin\\n }
expect eof
exit
"
eof;
    $list = shell_exec($cmd);

    $objects = array();
    foreach(explode("\r\n", $list) as $line) {
        if (preg_match('/^(.+)=(.*)$/', $line, $d)) {
            list($dummy, $key, $value) = $d;
            $objects[$key] = $value;
        }
    }

    return $objects;
}

function setattributes($slot, $pin, $handle, $attributes)
{
    $params = "";
    foreach ($attributes as $k => $v) { $params .= "$k=\"$v\" ";}
    printf("setattributes slot: %s attributes: %s\n", $slot, $params);
    $cmd = <<<eof
/usr/bin/expect -c "
spawn -noecho /usr/safenet/lunaclient/bin/cmu setattribute -slot=$slot -handle=$handle $params
expect slot { sleep .001; send $pin\\n }
expect eof
exit
"
eof;
    $list = shell_exec($cmd);
}

function importkey($slot, $pin, $path)
{
    printf("importkey slot: %s path: %s\n", $slot, $path);
    $cmd = <<<eof
/usr/bin/expect -c "
spawn /usr/safenet/lunaclient/bin/cmu importkey -slot=$slot -keyalg RSA -in $path
expect slot { sleep .001; send $pin\\n }
expect eof
exit
"
eof;
    return shell_exec($cmd);
}

function genkey($slot, $pin, $label)
{
    printf("gen slot: %s label: %s\n", $slot, $label);
    $cmd = <<<eof
/usr/bin/expect -c "
spawn /usr/safenet/lunaclient/bin/cmu gen -slot=$slot -modulusBits=2048 -publicExp=65537 -sign=T -verify=T -labelPublic=$label.pub -labelPrivate=$label.pri
expect slot { sleep .001; send $pin\\n }
expect uxiliary { send 1\\n }
expect eof
exit
"
eof;
    return shell_exec($cmd);
}

function delkey($slot, $pin, $handles)
{
    foreach($handles as $obj) {
        $handle = $obj['handle'];
        printf("delete slot: %s handle: %s label: %s\n", $slot, $handle, $obj['label']);
        $cmd = <<<eof
/usr/bin/expect -c "
spawn /usr/safenet/lunaclient/bin/cmu delete -slot=$slot -handle=$handle -force
expect slot { sleep .001; send $pin\\n }
expect eof
exit
"
eof;
        shell_exec($cmd);
    }
}

function selfsign($slot, $pin, $label, $handle_priv, $cn, $serial)
{
    printf("selfsign slot: %s handle: %s label: %s cn: %s serial: %s\n", $slot, $handle_priv, $label, $cn, $serial);
    $cmd = <<<eof
/usr/bin/expect -c "
spawn /usr/safenet/lunaclient/bin/cmu selfsign -slot=$slot -privatehandle=$handle_priv -sha256withrsa -C=DK -O=WAYF -CN="$cn" -startDate=20150101 -endDate=20251231 -serialNumber=$serial -label=$label.crt
expect slot { sleep .001; send $pin\\n }
expect eof
exit
"
eof;
    return shell_exec($cmd);
}

function exportpem($slot, $pin, $handles)
{
    foreach($handles as $handle => $obj) {
        $label = $obj['label'];
        printf("export slot: %s handle: %s file: %s\n", $slot, $handle, $label);
        $cmd = <<<eof
/usr/bin/expect -c "
spawn /usr/safenet/lunaclient/bin/cmu export -slot=$slot -handle=$handle -outputFile=$label.pem
expect slot { sleep .001; send $pin\\n }
expect eof
exit
"
eof;
        shell_exec($cmd);
    }
}
}
