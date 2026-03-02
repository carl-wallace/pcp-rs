rm -rf ./target/pkits_ml_dsa_44
./target/release/pcp-rs -c -x ./PKITS_data/certs -r ./PKITS_data/crls/ -s ./config/ss_44.json -g ./config/gen_44.json
rm -rf ./target/pkits_ml_dsa_44/keys

rm -rf ./target/pkits_ml_dsa_65
./target/release/pcp-rs -c -x ./PKITS_data/certs -r ./PKITS_data/crls/ -s ./config/ss_65.json -g ./config/gen_65.json
rm -rf ./target/pkits_ml_dsa_65/keys

rm -rf ./target/pkits_ml_dsa_87
./target/release/pcp-rs -c -x ./PKITS_data/certs -r ./PKITS_data/crls/ -s ./config/ss_87.json -g ./config/gen_87.json
rm -rf ./target/pkits_ml_dsa_87/keys

rm -rf ./target/pkits_slh_dsa_sha2_128s
./target/release/pcp-rs -c -x ./PKITS_data/certs -r ./PKITS_data/crls/ -s ./config/ss_sha2_128s.json -g ./config/gen_sha2_128s.json
rm -rf ./target/pkits_slh_dsa_sha2_128s/keys

rm -rf ./target/pkits_slh_dsa_sha2_128f
./target/release/pcp-rs -c -x ./PKITS_data/certs -r ./PKITS_data/crls/ -s ./config/ss_sha2_128f.json -g ./config/gen_sha2_128f.json
rm -rf ./target/pkits_slh_dsa_sha2_128f/keys

rm -rf ./target/pkits_slh_dsa_sha2_192s
./target/release/pcp-rs -c -x ./PKITS_data/certs -r ./PKITS_data/crls/ -s ./config/ss_sha2_192s.json -g ./config/gen_sha2_192s.json
rm -rf ./target/pkits_slh_dsa_sha2_192s/keys

rm -rf ./target/pkits_slh_dsa_sha2_192f
./target/release/pcp-rs -c -x ./PKITS_data/certs -r ./PKITS_data/crls/ -s ./config/ss_sha2_192f.json -g ./config/gen_sha2_192f.json
rm -rf ./target/pkits_slh_dsa_sha2_192f/keys

rm -rf ./target/pkits_slh_dsa_sha2_256s
./target/release/pcp-rs -c -x ./PKITS_data/certs -r ./PKITS_data/crls/ -s ./config/ss_sha2_256s.json -g ./config/gen_sha2_256s.json
rm -rf ./target/pkits_slh_dsa_sha2_256s/keys

rm -rf ./target/pkits_slh_dsa_sha2_256f
./target/release/pcp-rs -c -x ./PKITS_data/certs -r ./PKITS_data/crls/ -s ./config/ss_sha2_256f.json -g ./config/gen_sha2_256f.json
rm -rf ./target/pkits_slh_dsa_sha2_256f/keys

rm -rf ./target/pkits_slh_dsa_shake_128s
./target/release/pcp-rs -c -x ./PKITS_data/certs -r ./PKITS_data/crls/ -s ./config/ss_shake_128s.json -g ./config/gen_shake_128s.json
rm -rf ./target/pkits_slh_dsa_shake_128s/keys

rm -rf ./target/pkits_slh_dsa_shake_128f
./target/release/pcp-rs -c -x ./PKITS_data/certs -r ./PKITS_data/crls/ -s ./config/ss_shake_128f.json -g ./config/gen_shake_128f.json
rm -rf ./target/pkits_slh_dsa_shake_128f/keys

rm -rf ./target/pkits_slh_dsa_shake_192s
./target/release/pcp-rs -c -x ./PKITS_data/certs -r ./PKITS_data/crls/ -s ./config/ss_shake_192s.json -g ./config/gen_shake_192s.json
rm -rf ./target/pkits_slh_dsa_shake_192s/keys

rm -rf ./target/pkits_slh_dsa_shake_192f
./target/release/pcp-rs -c -x ./PKITS_data/certs -r ./PKITS_data/crls/ -s ./config/ss_shake_192f.json -g ./config/gen_shake_192f.json
rm -rf ./target/pkits_slh_dsa_shake_192f/keys

rm -rf ./target/pkits_slh_dsa_shake_256s
./target/release/pcp-rs -c -x ./PKITS_data/certs -r ./PKITS_data/crls/ -s ./config/ss_shake_256s.json -g ./config/gen_shake_256s.json
rm -rf ./target/pkits_slh_dsa_shake_256s/keys

rm -rf ./target/pkits_slh_dsa_shake_256f
./target/release/pcp-rs -c -x ./PKITS_data/certs -r ./PKITS_data/crls/ -s ./config/ss_shake_256f.json -g ./config/gen_shake_256f.json
rm -rf ./target/pkits_slh_dsa_shake_256f/keys
