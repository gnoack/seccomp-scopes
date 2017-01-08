#!/bin/sh
# Checks that an object file doesn't have the BADBPF marker in it.
F=$1
strings $F | grep BADBPF
if [ $? -eq 0 ]; then
    echo "FAIL: Not all occurences of the BADBPF marker were optimized away."
    exit 1
fi

echo "OK: All optimizations working."
