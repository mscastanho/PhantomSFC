cd $(dirname "$0")
../build/sfcapp -c 0x2 -n 2 -m 1024 -- -p 3 -t classifier -f ../config/classifier.cfg
cd -