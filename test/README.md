This directory contains sample capture files to demonstrate and test the
DLEP wireshark plugin.

Capture Files
-------------

* dlep.pcapng - Sample capture of DLEP startup operation using
  the MIT LL DLEP implementation.

Plugin Tests
------------

See 1.10 of <wireshark_root>/doc/README.dissector:

```bash
cd <wireshark_root>
./tools/checkAPIs.pl          ./plugins/epan/dlep/packet-dlep.*
./tools/checkhf.pl            ./plugins/epan/dlep/packet-dlep.*
./tools/checkfiltername.pl    ./plugins/epan/dlep/packet-dlep.*
./tools/cppcheck/cppcheck.sh  ./plugins/epan/dlep/packet-dlep.*
cd <wireshark_root>/build/run/
../../tools/fuzz-test.sh  ../../plugins/epan/dlep/test/dlep.pcapng
```

Note: `cppcheck.sh` relies on `cppcheck` being available in your path.
Note: `fuzz-test.sh` relies on `tshark`, `editcap`, and `capinfos` in the
present working directory.
