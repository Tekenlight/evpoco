LIB=/usr/local/lib/libevnet.so.60   # use the exact .so that produced the crash

# 1) Get the function's start address inside the .so (ELF VMA)
SYM=$(nm -an --demangle "$LIB" | \
      awk '/EVTCPServer::handleConnSocketConnected/{print $1; exit}')

echo $SYM
# 2) Add the +0xc0 offset from the backtrace
ADDR=$(printf "0x%x\n" $((0x$SYM + 0xc0)))

# 3) Resolve to file:line (needs DWARF)
addr2line -e "$LIB" -fC "$ADDR"

