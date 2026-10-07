#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "Usage: scripts/generate-mtls-certs.sh OUTPUT_DIR" >&2
    exit 2
fi

output_dir=$1
case "$output_dir" in
    /*) ;;
    *) output_dir="$(pwd -P)/$output_dir" ;;
esac

umask 077
mkdir -p "$(dirname "$output_dir")"
mkdir -m 700 "$output_dir"
chmod 700 "$output_dir"
work_dir="$output_dir/.work"
mkdir "$work_dir"
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

mkdir "$work_dir/newcerts"
: > "$work_dir/index.txt"
printf '1000\n' > "$work_dir/serial"

config_output_dir=$output_dir
config_work_dir=$work_dir
if [ "${RUNNER_OS:-}" = "Windows" ]; then
    config_output_dir=$(cygpath --mixed "$output_dir")
    config_work_dir=$(cygpath --mixed "$work_dir")
    export MSYS2_ARG_CONV_EXCL=/CN=
fi

cat > "$work_dir/openssl.cnf" <<EOF
[ ca ]
default_ca = kmesh_ca

[ kmesh_ca ]
database = $config_work_dir/index.txt
new_certs_dir = $config_work_dir/newcerts
serial = $config_work_dir/serial
certificate = $config_output_dir/ca-cert.pem
private_key = $config_output_dir/ca-key.pem
default_md = sha384
default_days = 26784
policy = policy

[ policy ]
commonName = supplied

[ req ]
distinguished_name = req_dn
prompt = no

[ req_dn ]
CN = kmesh-build

[ v3_ca ]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ server_cert ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:kmesh.internal
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ client_cert ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$output_dir/ca-key.pem"
openssl req -new -key "$output_dir/ca-key.pem" -out "$work_dir/ca.csr" \
    -subj "/CN=kmesh-build-root" -config "$work_dir/openssl.cnf"

not_before=$(date -u +%Y%m%d%H%M%SZ)
not_after=20991231235959Z
openssl ca -selfsign -batch -config "$work_dir/openssl.cnf" \
    -keyfile "$output_dir/ca-key.pem" -in "$work_dir/ca.csr" \
    -out "$output_dir/ca-cert.pem" -startdate "$not_before" \
    -enddate "$not_after" -extensions v3_ca

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$output_dir/server-key.pem"
openssl req -new -key "$output_dir/server-key.pem" -out "$work_dir/server.csr" \
    -subj "/CN=kmesh.internal" -config "$work_dir/openssl.cnf"
openssl ca -batch -config "$work_dir/openssl.cnf" -in "$work_dir/server.csr" \
    -out "$output_dir/server-cert.pem" -startdate "$not_before" \
    -enddate "$not_after" -extensions server_cert

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$output_dir/client-key.pem"
openssl req -new -key "$output_dir/client-key.pem" -out "$work_dir/client.csr" \
    -subj "/CN=kmesh-build-client" -config "$work_dir/openssl.cnf"
openssl ca -batch -config "$work_dir/openssl.cnf" -in "$work_dir/client.csr" \
    -out "$output_dir/client-cert.pem" -startdate "$not_before" \
    -enddate "$not_after" -extensions client_cert

chmod 600 "$output_dir/ca-key.pem" "$output_dir/server-key.pem" "$output_dir/client-key.pem"
chmod 600 "$output_dir/ca-cert.pem" "$output_dir/server-cert.pem" "$output_dir/client-cert.pem"
openssl verify -CAfile "$output_dir/ca-cert.pem" -purpose sslserver "$output_dir/server-cert.pem"
openssl verify -CAfile "$output_dir/ca-cert.pem" -purpose sslclient "$output_dir/client-cert.pem"

printf 'Generated mTLS certificates in %s\n' "$output_dir"
