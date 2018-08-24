cd $(dirname "$0")
../build/sfcapp -c 0x2 -n 2 -m 4096 -- -p 3 -t forwarder -f ../config/forwarder.cfg
cd -