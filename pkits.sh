rm -rf ./target/pkits_ml_dsa_44
./target/release/pcp-rs -c -x ~/Desktop/PKITS_data/certs -r ~/PKITS_data/crls/ -s ./ss_44.json -g ./gen_44.json

rm -rf ./target/pkits_ml_dsa_65
./target/release/pcp-rs -c -x ~/Desktop/PKITS_data/certs -r ~/PKITS_data/crls/ -s ./ss_65.json -g ./gen_65.json

rm -rf ./target/pkits_ml_dsa_87
./target/release/pcp-rs -c -x ~/Desktop/PKITS_data/certs -r ~/PKITS_data/crls/ -s ./ss_87.json -g ./gen_87.json
