cd $(dirname "$0")
../sfc/build/sfcapp -c 0x2 -n 2 -m 1024 -- -p 3 -t proxy -f ../config/proxy1.cfg
cd -