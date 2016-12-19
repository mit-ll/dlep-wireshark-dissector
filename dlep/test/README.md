This directory contains sample capture files to demonstrate and test the
DLEP wireshark plugin.

Capture Files
-------------

* capture1.pcapng - Capture of DLEP startup operation using the MIT LL DLEP
  implementation in CORE at https://llcad-github.llan.ll.mit.edu/dlep/dlep

Plugin Tests
------------

See 1.11 of <wireshark_root>/doc/README.developer:

```
cd <wireshark_root>
perl ./tools/checkAPIs.pl ./plugins/dlep/packet-dlep.c
perl ./tools/checkhf.pl ./plugins/dlep/packet-dlep.c
perl ./tools/checkfiltername.pl ./plugins/dlep/packet-dlep.c
./tools/fuzz-test.sh ./plugins/dlep/test/capture1.pcapng
```
