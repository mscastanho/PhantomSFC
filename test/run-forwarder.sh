cd $(dirname "$0")
../sfc/build/sfcapp -c 0x2 -n 2 -m 4096 -- -p 3 -t forwarder -c ../config/forwarder.cfg
cd -