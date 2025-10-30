#!/bin/bash

base_dir="${PWD}/test/workdir"
bin_dir="${base_dir}/bin"
pid_dir="${base_dir}/run"
logs_dir="${base_dir}/logs"
certs_dir="${base_dir}/certs"
credentials_dir="${base_dir}/device-credentials"
device_credentials="${credentials_dir}/creds.bin"
ov_dir="${base_dir}/ovs"

device_ca_key="${certs_dir}/device_ca.key"
device_ca_crt="${device_ca_key/\.key/.crt}"
device_ca_pub="${device_ca_key/\.key/.pub}"
device_ca_subj="/C=US/O=FDO/CN=Device CA"

manufacturer_service_name="manufacturer"
manufacturer_dns=manufacturer
manufacturer_ip=127.0.0.1
manufacturer_port=8038
manufacturer_pid_file="${pid_dir}/manufacturer.pid"
manufacturer_log="${logs_dir}/${manufacturer_dns}.log"
manufacturer_key="${certs_dir}/manufacturer.key"
manufacturer_crt="${manufacturer_key/\.key/.crt}"
manufacturer_pub="${manufacturer_key/\.key/.pub}"
manufacturer_subj="/C=US/O=FDO/CN=Manufacturer"
manufacturer_service="${manufacturer_dns}:${manufacturer_port}"
manufacturer_url="http://${manufacturer_service}"
manufacturer_health_url="${manufacturer_url}/health"

rendezvous_service_name="rendezvous"
rendezvous_dns=rendezvous
rendezvous_ip=127.0.0.1
rendezvous_port=8041
rendezvous_pid_file="${pid_dir}/rendezvous.pid"
rendezvous_log="${logs_dir}/${rendezvous_dns}.log"
rendezvous_service="${rendezvous_dns}:${rendezvous_port}"
rendezvous_url="http://${rendezvous_service}"
rendezvous_health_url="${rendezvous_url}/health"

owner_service_name="owner"
owner_dns=owner
owner_ip=127.0.0.1
owner_port=8043
owner_pid_file="${pid_dir}/owner.pid"
owner_log="${logs_dir}/${owner_dns}.log"
owner_key="${certs_dir}/owner.key"
owner_crt="${owner_key/\.key/.crt}"
owner_pub="${owner_key/\.key/.pub}"
owner_subj="/C=US/O=FDO/CN=Owner"
owner_service="${owner_dns}:${owner_port}"
owner_url="http://${owner_service}"
owner_health_url="${owner_url}/health"
owner_ov="${base_dir}/owner.ov"

  
# Install go-fdo-server and go-fdo-client
dnf install -y make golang
mkdir -p ${base_dir}/bin
mkdir -p ${base_dir}/certs
mkdir -p ${base_dir}/device-credentials
mkdir -p ${base_dir}/logs
mkdir -p ${base_dir}/run
mkdir -p ${base_dir}/ovs
make && install -m 755 go-fdo-server ${base_dir}/bin
go install github.com/fido-device-onboard/go-fdo-client@latest
export PATH=$PATH:$(go env GOPATH)/bin

# Generate certs
service=${manufacturer_service_name}
service_key="${service}_key"
service_crt="${service}_crt"
service_pub="${service}_pub"
service_subj="${service}_subj"

openssl ecparam -name prime256v1 -genkey -outform der -out "${!service_key}"
openssl req -x509 -key "${!service_key}" -keyform der -subj "${!service_subj}" -days 365 -out "${!service_crt}"
openssl x509 -in "${!service_crt}" -pubkey -noout -out "${!service_pub}"
chmod g+r "${!service_key}" "${!service_crt}" "${!service_pub}"

service=${owner_service_name}
service_key="${service}_key"
service_crt="${service}_crt"
service_pub="${service}_pub"
service_subj="${service}_subj"

openssl ecparam -name prime256v1 -genkey -outform der -out "${!service_key}"
openssl req -x509 -key "${!service_key}" -keyform der -subj "${!service_subj}" -days 365 -out "${!service_crt}"
openssl x509 -in "${!service_crt}" -pubkey -noout -out "${!service_pub}"
chmod g+r "${!service_key}" "${!service_crt}" "${!service_pub}"

device_ca_key="${certs_dir}/device_ca.key"
device_ca_crt="${device_ca_key/\.key/.crt}"
device_ca_pub="${device_ca_key/\.key/.pub}"
device_ca_subj="/C=US/O=FDO/CN=Device CA"

openssl ecparam -name prime256v1 -genkey -outform der -out "${device_ca_key}"
openssl req -x509 -key "${device_ca_key}" -keyform der -subj "${device_ca_subj}" -days 365 -out "${device_ca_crt}"
openssl x509 -in "${device_ca_crt}" -pubkey -noout -out "${device_ca_pub}"
chmod g+r "${device_ca_key}" "${device_ca_crt}" "${device_ca_pub}"

# Set hostnames
echo "${manufacturer_ip} ${manufacturer_dns}" | sudo tee -a /etc/hosts
echo "${rendezvous_ip} ${rendezvous_dns}" | sudo tee -a /etc/hosts
echo "${owner_ip} ${owner_dns}" | sudo tee -a /etc/hosts

# Start manufacturer server
nohup "${bin_dir}/go-fdo-server" --debug manufacturing "${manufacturer_dns}:${manufacturer_port}" --db-type sqlite --db-dsn "file:${base_dir}/manufacturer.db" \
    --manufacturing-key="${manufacturer_key}" \
    --owner-cert="${owner_crt}" \
    --device-ca-cert="${device_ca_crt}" \
    --device-ca-key="${device_ca_key}" &> "${manufacturer_log}" &
echo -n $! > "${manufacturer_pid_file}"
sleep 10
curl --silent --output /dev/null --write-out '%{http_code}' "${manufacturer_health_url}"

# Start rendezvous server
nohup "${bin_dir}/go-fdo-server" --debug rendezvous "${rendezvous_dns}:${rendezvous_port}" --db-type sqlite --db-dsn "file:${base_dir}/rendezvous.db" &> "${rendezvous_log}" &
echo -n $! > "${rendezvous_pid_file}"
sleep 10
curl --silent --output /dev/null --write-out '%{http_code}' "${rendezvous_health_url}"

# Start owner server
nohup "${bin_dir}/go-fdo-server" --debug owner "${owner_dns}:${owner_port}" --db-type sqlite --db-dsn "file:${base_dir}/owner.db" \
    --owner-key="${owner_key}" \
    --device-ca-cert="${device_ca_crt}" &> "${owner_log}" &
echo -n $! > "${owner_pid_file}"
sleep 10
curl --silent --output /dev/null --write-out '%{http_code}' "${owner_health_url}"

# Set Rendezvous Info (RendezvousInfo)
curl --fail --verbose --silent --request GET --header 'Content-Type: text/plain' "${manufacturer_url}/api/v1/rvinfo"
rendezvous_info="[{\"dns\": \"${rendezvous_dns}\", \"device_port\": \"${rendezvous_port}\", \"protocol\": \"http\", \"ip\": \"${rendezvous_ip}\", \"owner_port\": \"${rendezvous_port}\"}]"
curl --fail --verbose --silent \
    --request POST \
    --header 'Content-Type: text/plain' \
    --data-raw "${rendezvous_info}" \
    "${manufacturer_url}/api/v1/rvinfo"

# Device initialization
cd ${credentials_dir}
$(go env GOPATH)/bin/go-fdo-client --blob "${device_credentials}" --debug device-init "${manufacturer_url}" --device-info=gotest --key ec256
cd -

# Get credential GUID
guid=$($(go env GOPATH)/bin/go-fdo-client --blob "${device_credentials}" print | grep GUID | awk '{print $2}')
echo "⭐ Device initialized with GUID: ${guid}"

# Export manufacturer ov
ov_file="${ov_dir}/${guid}.ov"
curl --fail --verbose --silent "${manufacturer_url}/api/v1/vouchers/${guid}" -o "${ov_file}"

# Import manufacturer ov to owner
curl --fail --verbose --silent --request POST --data-binary "${ov_file}" "${owner_url}/api/v1/owner/vouchers"

# Check if 'RVTO2Addr' is configured on owner side
curl --fail --verbose --silent \
    --header 'Content-Type: text/plain' \
    "${owner_url}/api/v1/owner/redirect"

# RVTO2Addr not found, create it
rvto2addr="[{\"ip\": \"${owner_ip}\", \"dns\": \"${owner_dns}\", \"port\": \"${owner_port}\", \"protocol\": \"${5:-http}\"}]"
curl --fail --verbose --silent \
    --request POST \
    --header 'Content-Type: text/plain' \
    --data-raw "${rvto2addr}" \
    "${owner_url}/api/v1/owner/redirect"

#  Trigger TO0 on Owner server"
curl --fail --verbose --silent "${owner_url}/api/v1/to0/${guid}"

# Run FIDO Device Onboard "
log="${logs_dir}/onboarding-device-${guid}.log"
>"${log}"
$(go env GOPATH)/bin/go-fdo-client --blob "${device_credentials}" onboard --key ec256 --kex ECDH256 --debug | tee "${log}"
grep -q 'FIDO Device Onboard Complete' "${log}"

