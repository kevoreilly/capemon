#!/bin/sh

# directory in which the main repository of Cuckoo Sandbox can be found
if [ -z "$CUCKOODIR" ]; then
    CUCKOODIR=../cuckoo
fi

# target filename - in case of testing with custom dll's one may wish to
# use a different filename, such as "cuckoomon_bson.dll"
if [ -z "$CUCKOOMON" ]; then
    CUCKOOMON=cuckoomon.dll
fi

make && cp cuckoomon.dll "$CUCKOODIR/analyzer/windows/dll/$CUCKOOMON"
