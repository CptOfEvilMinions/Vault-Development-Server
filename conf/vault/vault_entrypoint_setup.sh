#!/bin/sh
set -e

#### ENV vars ####
export VAULT_ADDR=http://127.0.0.1:8200

# Install tools
apk add curl jq

##### WAIT FOR CONSUL ######
echo "[*] - $(date) - Wait for Consul to start"
while [[ "$(curl -s -o /dev/null -w ''%{http_code}'' http://consul:8500/v1/status/leader)" != "200" ]]; do sleep 3; done
echo "[+] - $(date) - Consul has started"

##### WAIT FOR Vault ######
echo "[*] - $(date) - Wait for Vault to start"
while [[ "$(curl -s -o /dev/null -w ''%{http_code}'' http://127.0.0.1:8200/v1/sys/health)" != "501" ]] && [[ "$(curl -s -o /dev/null -w ''%{http_code}'' http://127.0.0.1:8200/v1/sys/health)" != "503" ]]; do sleep 3; done
echo "[+] - $(date) - Vault has started"

# Check if Vault has been initialized
if [ $(curl -s http://127.0.0.1:8200/v1/sys/health | jq .initialized) = "false" ]
then
    # Change permissions of /vault/data directory
    chown vault:vault -R /vault/data

    # Vault init
    echo "[*] - $(date) - Initializing Vault"
    vault operator init -key-shares=1 -key-threshold=1 > /vault/data/vault_keys.txt
    echo "[+] - $(date) - Vault initialized"

    # Extract keys
    vault_unseal_key=$(cat /vault/data/vault_keys.txt | grep 'Unseal Key 1' | awk '{print $4}')
    vault_root_token=$(cat /vault/data/vault_keys.txt | grep 'Initial Root Token:' | awk '{print $4}')
    cat /vault/data/vault_keys.txt 

    # UNseal Vault
    vault operator unseal ${vault_unseal_key}
    echo "[*] - $(date) - Vault has been UNsealed"

    # Log into Vault
    vault login ${vault_root_token}

    # # Write admin policy to Vault
    vault policy write admin-users /vault/policies/vault-policy-admin-user.hcl
    echo "[+] - $(date) - Uploaded Vault admin policy"

    #### Enable LDAP auth ####
    vault auth enable ldap 
    echo "[+] - $(date) - Enabled Vault LDAP auth"

    vault write auth/ldap/config $(cat /vault/config/vault-ldap-config.ldif | \
    sed "s#{{ LDAP_URL }}#$(cat /run/secrets/vault-dev-server-ldap-bind-url)#g" | \
    sed "s#{{ LDAP_DOMAIN_NAME }}#$(cat /run/secrets/vault-dev-server-ldap-bind-url | awk -F'.' '{print $2}')#g" | \
    sed "s#{{ LDAP_DOMAIN_TLD }}#$(cat /run/secrets/vault-dev-server-ldap-bind-url | awk -F'.' '{print $3}')#g" | \
    sed "s#{{ BIND_USERNAME }}#$(cat /run/secrets/vault-dev-server-ldap-bind-username)#g" | \
    sed "s#{{ BIND_PASSWORD }}#$(cat /run/secrets/vault-dev-server-ldap-bind-password)#g")
    echo "[+] - $(date) - Configured Vault LDAP auth"

    # Make LDAP admins assing to admin policy
    vault write auth/ldap/groups/admins policies=admin-users
    echo "[+] - $(date) - All LDAP admins have been granted the Vault admin policy"

    ### Enable root PKI ###
    vault secrets enable pki
    echo "[+] - $(date) - Enabled Vault PKI"
    
    # Create CA bundle
    apk add openssl
    cat /run/secrets/*-rootCA-cert > /tmp/ca_bundle.pem
    openssl rsa -in /run/secrets/*-rootCA-key >> /tmp/ca_bundle.pem
    echo "[+] - $(date) - Created Root CA bundle for Vault"

    # Upload CA bundle
    # https://rcronco.github.io/lemur_vault/Vault_CA.html
    vault write pki/config/ca pem_bundle="@/tmp/ca_bundle.pem"
    vault write pki/roles/$(openssl x509 -noout -subject -in /run/secrets/*-rootCA-cert -nameopt multiline | grep commonName | awk '{print $3}' | tr . -)-role \
        allow_any_name=true \
        allow_subdomains=true \
        allow_ip_sans=true \
        max_ttl="72h" \
        allow_localhost=true
    echo "[+] - $(date) - Uploaded Root CA bundle to Vault"

    echo -e "\n\n######################################################################"
    echo "#                     Vault Initializing Complete"
    echo "######################################################################"

else
    # Extract Vault unseal key
    vault_unseal_key=$(cat /vault/data/vault_keys.txt | grep 'Unseal Key 1' | awk '{print $4}')

    # UNseal Vault
    vault operator unseal ${vault_unseal_key}
    echo -e "\n\n######################################################################"
    echo "#                     Vault has been UNsealed"
    echo "######################################################################"
fi
