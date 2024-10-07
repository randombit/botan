#/bin/bash

#
# Sets up a TPM2 simulator that is running behind a user-space TPM2 resource
# manager. Applications can discover the resource manager via D-Bus and use
# the resource manager's TCTI (aka. tabrmd).
#
# The simulator is populated with persistent keys for testing.
#
# If you need the simulated TPM 2.0 setup in your deveolpment environment, you
# can run this script manually. If something goes wrong, you can re-initialize
# the TPM 2.0 simulator by running:
#
#   kill $(pgrep swtpm); kill $(pgrep tpm2-abrmd); sh src/scripts/ci/start_tpm2_simulator.sh
#

set -e

tmp_dir="${1:-/tmp/mytpm2}"
dbus_name="net.randombit.botan.tabrmd"
tcti_name="tabrmd"
tcti_conf="bus_name=${dbus_name},bus_type=session"
tcti="${tcti_name}:${tcti_conf}"
test_pwd="password"
persistent_rsa_key_handle="0x81000008"
persistent_ecc_key_handle="0x81000010"

if ! systemctl is-active --quiet dbus; then
    echo "DBus is not running. Starting it..."
    sudo systemctl start dbus
fi

echo "Setting up TPM..."
swtpm_setup --create-config-files overwrite

# "Endorsement Key"  - baked into the TPM (signed by the manufacturer)
# "Platform Key"     - signed serial number of the EK (signed by the OEM; eg. the laptop manufacturer)
# "Storage Root Key" - created by the user (signed by the EK)
rm -fR $tmp_dir && mkdir $tmp_dir
swtpm_setup --tpmstate $tmp_dir    \
            --create-ek-cert       \
            --create-platform-cert \
            --create-spk           \
            --overwrite --tpm2     \
            --display

echo "Starting TPM2 simulator..."
swtpm socket --tpmstate dir=$tmp_dir     \
             --ctrl type=tcp,port=2322   \
             --server type=tcp,port=2321 \
             --flags not-need-init       \
             --daemon --tpm2

echo "Starting TPM2 resource manager..."
tpm2-abrmd --tcti=swtpm --session --dbus-name="${dbus_name}" &
echo "Resource manager running as PID: $!"

echo "Waiting a for the dbus name to be available..."
waited=5
while ! dbus-send --session --dest=org.freedesktop.DBus --type=method_call --print-reply \
    /org/freedesktop/DBus org.freedesktop.DBus.ListNames | grep -q "${dbus_name}"; do
    sleep 1
    echo "..."
    waited=$((waited - 1))
    if [ $waited -eq 0 ]; then
        echo "Failed to start the TPM2 resource manager"
        exit 1
    fi
done

echo "Create a key to play with..."
tpm2_createprimary --tcti="$tcti"          \
                   --hierarchy e           \
                   --hash-algorithm sha256 \
                   --key-algorithm rsa     \
                   --key-context $tmp_dir/primary.ctx


# Use default key template of tpm2_create for rsa.
# This means that the key will NOT be "restricted".
tpm2_create --tcti="$tcti"                        \
            --parent-context $tmp_dir/primary.ctx \
            --key-algorithm rsa                   \
            --public $tmp_dir/rsa.pub             \
            --private $tmp_dir/rsa.priv           \
            --key-auth $test_pwd
tpm2_load --tcti="$tcti"                        \
          --parent-context $tmp_dir/primary.ctx \
          --public $tmp_dir/rsa.pub             \
          --private $tmp_dir/rsa.priv           \
          --key-context $tmp_dir/rsa.ctx
tpm2_evictcontrol --tcti="$tcti"                    \
                  --hierarchy o                     \
                  --object-context $tmp_dir/rsa.ctx \
                  $persistent_rsa_key_handle

# Do the same for ecc
tpm2_create --tcti="$tcti"                        \
            --parent-context $tmp_dir/primary.ctx \
            --key-algorithm ecc                   \
            --public $tmp_dir/ecc.pub             \
            --private $tmp_dir/ecc.priv           \
            --key-auth $test_pwd
tpm2_load --tcti="$tcti"                        \
          --parent-context $tmp_dir/primary.ctx \
          --public $tmp_dir/ecc.pub             \
          --private $tmp_dir/ecc.priv           \
          --key-context $tmp_dir/ecc.ctx
tpm2_evictcontrol --tcti="$tcti"                    \
                  --hierarchy o                     \
                  --object-context $tmp_dir/ecc.ctx \
                  $persistent_ecc_key_handle

echo "Effectively disable dictionary attack lockout..."
tpm2_dictionarylockout --tcti="$tcti"     \
                       --setup-parameters \
                       --max-tries=1000   \
                       --recovery-time=1  \
                       --lockout-recovery-time=1

# Propagate relevant information about the simulated TPM 2.0 setup to
# the test scripts that are going to run, if we're running on GitHub Actions.
if [ -n "$GITHUB_ACTIONS" ]; then
    echo "Setting up GitHub Actions environment..."
    echo "BOTAN_TPM2_TCTI_NAME=$tcti_name"                                 >> $GITHUB_ENV
    echo "BOTAN_TPM2_TCTI_CONF=$tcti_conf"                                 >> $GITHUB_ENV
    echo "BOTAN_TPM2_PERSISTENT_KEY_AUTH_VALUE=$test_pwd"                  >> $GITHUB_ENV
    echo "BOTAN_TPM2_PERSISTENT_RSA_KEY_HANDLE=$persistent_rsa_key_handle" >> $GITHUB_ENV
    echo "BOTAN_TPM2_PERSISTENT_ECC_KEY_HANDLE=$persistent_ecc_key_handle" >> $GITHUB_ENV
fi
