# cmu
cmu.php is a thin PHP scripting layer on top of the SafeNet cmu (Certificate Management Utility) command

Given a slot number and a pin from the environment vars: CMU_SLOT and CMU_PIN it allows you to:

    list objects            cmu::listobjects
    import existing keys    cmu::importkey
    filter objects by label cmu::filterbylabel
    generate keys           cmu::genkey
    delete keys             cmu::delkey
    selfsign certs          cmu::selfsign
    export certs in pem     cmu::exportpem

It expects the expect utility to be installed

