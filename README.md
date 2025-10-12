

## Integrate JWT token based authentication for Postgrest API

Ensure that postgresSQL pod is `running`. In our case api-auth namespace has a postgresSQL db is running.
```yaml
kubectl get pods -n api-auth

NAME                             READY   STATUS    RESTARTS   AGE
postgres-6748f9856c-pnz8r        1/1     Running   0          118m
```
Then we need to run following script to run to prepare necessary roles for JWT

```bash
# 1. Get the Pod name
PG_POD=$(kubectl get pods -n api-auth -l app=postgres -o jsonpath='{.items[0].metadata.name}')

# 2. Execute SQL for PostgREST roles and permissions
kubectl exec -it -n api-auth $PG_POD -- psql -U postgres -d api_db -c "
-- PostgREST Authenticator Role with password
CREATE ROLE authenticator NOINHERIT LOGIN PASSWORD '$(kubectl get secret postgres-credentials -n api-auth -o jsonpath='{.data.PG_PASS_AUTH}' | base64 -d)';

-- User Roles
CREATE ROLE web_anon NOLOGIN;
CREATE ROLE inventory_user NOLOGIN;

-- Grant impersonation rights to the authenticator
GRANT web_anon TO authenticator;
GRANT inventory_user TO authenticator;

-- Anonymous (read-only) permissions
GRANT USAGE ON SCHEMA public TO web_anon;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO web_anon;

-- Authenticated (CRUD) permissions
GRANT ALL ON ALL TABLES IN SCHEMA public TO inventory_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO inventory_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO inventory_user;

#later I identify these to create a initial  TABLES
-- Create the table (using the modern IDENTITY method)
CREATE TABLE public.products (
    product_id bigint NOT NULL GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    product_name text NOT NULL,
    price numeric NOT NULL DEFAULT 0,
    description text
);

-- Ensure the public role (and thus all user roles) can see it
GRANT SELECT ON public.products TO web_anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.products TO inventory_user;
"
```

If we want to revoke access for anynomous user from viewing table we need to run this
```bash
REVOKE SELECT ON public.products FROM web_anon;
``` 

Now we deployed keycloak and expose url using ingress here in our case it is https: auth.muntashirislam.com. But in production setup we need to keep this into clusterIP service. 
Now we need to do following steps to configure keycloak service from keycloak console.

- Navigate to https://auth.muntashirislam.com/admin.

- Create Realm (e.g., my-postgrest-realm).

- Create Client (Client ID: postgrest_api, Client authentication: on).

- Credentials Tab: Note the Client Secret.

- Roles Tab: Create Realm Roles: web_user, inventory_user.

- Client Scopes: Ensure your roles are mapped to the access token under the JSON path: .resource_access.postgrest_api.roles.

- Map user (muntashir/admin) with the role

Now we also need JWKS endpoint for the authentication

```bash
curl -sS https://auth.muntashirislam.com/realms/my-postgrest-realm/protocol/openid-connect/certs > keycloak-jwks.json
cat keycloak-jwks.json | base64

```
Finally we put this base64 data into the deployment under the env variable `PGRST_JWT_SECRET`

now we can get the token from keycloak
```bash
ACCESS_TOKEN=$(
  curl -s --location 'https://auth.muntashirislam.com/realms/my-postgrest-realm/protocol/openid-connect/token' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'client_id=postgrest_api' \
    --data-urlencode 'username=muntashir' \
    --data-urlencode 'password=admin' \
    --data-urlencode 'grant_type=password' \
    --data-urlencode 'client_secret=<Client Secret>' \
    | jq -r '.access_token'
)

echo "Extracted Token: $ACCESS_TOKEN"
```
Then you can call CURD operation on api

```bash
curl -i -X POST 'https://api.muntashirislam.com/products' \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{"product_name": "Test Product2", "price": 200, "description": "Auth Test 2"}]'

HTTP/2 201 
date: Sun, 12 Oct 2025 01:52:07 GMT
content-length: 0
content-range: */*
strict-transport-security: max-age=31536000; includeSubDomains
``` 
But If we want to do this operation without token from keycloak

```bash
❯ curl -i -X POST 'https://api.muntashirislam.com/products' \
  -H "Content-Type: application/json" \
  -d '[{"product_name": "Test Product3", "price": 300, "description": "Auth Test 3"}]'

HTTP/2 401 
date: Sun, 12 Oct 2025 01:53:40 GMT
content-type: application/json; charset=utf-8
content-length: 92
proxy-status: PostgREST; error=42501
www-authenticate: Bearer
strict-transport-security: max-age=31536000; includeSubDomains

{"code":"42501","details":null,"hint":null,"message":"permission denied for table products"}%  
```

### installing using Hashicorp vault 
We are going to install vault for storing all the necessary secrets for our application deployments. First prepare all necessary values for installing helm charts for vault in vault-values.yaml file

```yaml
server:
  # Use the File storage backend for persistent data
  standalone:
    enabled: true

  # Persistence settings
  dataStorage:
    enabled: true
    # Requests 1GB of persistent storage
    size: 1Gi
    storageClass: "gp2" # Our cluster's StorageClass if needed

  # Service type to expose the UI/API
  service:
    type: ClusterIP

  # UI settings
  ui:
    enabled: true
    serviceType: ClusterIP
```
The install vault chart

```bash
helm repo add hashicorp https://helm.releases.hashicorp.com
helm install vault hashicorp/vault --namespace vault -f vault-values.yaml
```

Now we can see vault pods running in unseal conditions
```bash
k get pods -n vault

NAME                                    READY   STATUS    RESTARTS   AGE
vault-0                                 0/1     Running   0          3m28s
vault-agent-injector-556c5dd8fb-wcdtk   1/1     Running   0          3m28s
```
We now initialize vault (Following is demo data)

```bash
kubectl exec -it vault-0 -n vault -- /bin/sh

kubectl exec -it -n vault vault-0 -- vault operator init
Unseal Key 1: 1tDyzFVgaf36yFsJJIdZwqjQG3cDtJvgl+jiQhD6dvIg
Unseal Key 2: Vr+JVzTT95kQsmMOeK0zlySNKqEMUZuMQk35vDMGBqzO
Unseal Key 3: Tl6cQP7t+0VqOUxfkvIWbiBeCeEXwhwo8ooSNdaiQnyJ
Unseal Key 4: 1jwoJDdBKUQe3/j//t7SPpWPEuz6cbfNes6sN3Lazehl
Unseal Key 5: mLWl+2pgNVI//R4Cwdc5se83GL3DEc6aCVFzNK8yEb9c

Initial Root Token: hvs.cqjLOdguKyytSN0ETmppGZ3H

Vault initialized with 5 key shares and a key threshold of 3. Please securely
distribute the key shares printed above. When the Vault is re-sealed,
restarted, or stopped, you must supply at least 3 of these keys to unseal it
before it can start servicing requests.

Vault does not store the generated root key. Without at least 3 keys to
reconstruct the root key, Vault will remain permanently sealed!

It is possible to generate new unseal keys, provided you have a quorum of
existing unseal keys shares. See "vault operator rekey" for more information.

vault operator unseal po4J/KvzgrzTHjo5a3iEZcW+84oZ1g7ZBOQhceA0aJw=
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    1
Threshold       1
Version         1.20.4
Build Date      2025-09-23T13:22:38Z
Storage Type    file
Cluster Name    vault-cluster-d125f0b9
Cluster ID      aa114368-1a23-5ea1-7d53-9b4bdd78b5ba
HA Enabled      false
```

After running these command we can now find that the vault is in running state
```bash
k get pods -n vault

NAME                                    READY   STATUS    RESTARTS   AGE
vault-0                                 1/1     Running   0          12m
vault-agent-injector-556c5dd8fb-wcdtk   1/1     Running   0          12m
```

Now we need to prepare vault to use in kubernetes secret provider. We need to execute following steps

```bash
/ $ export VAULT_ADDR='http://127.0.0.1:8200'
/ $ vault login hvs.X24TmcMeJnhKtKlj4XKkr0Dl
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                  Value
---                  -----
token                hvs.X24TmcMeJnhKtKlj4XKkr0Dl
token_accessor       cs6Cl1Xba8ctLAe5TohWwBzB
token_duration       ∞
token_renewable      false
token_policies       ["root"]
identity_policies    []
policies             ["root"]
/ $ vault auth enable kubernetes
Success! Enabled kubernetes auth method at: kubernetes/
```
Configure Vault to use your cluster’s service account JWT and CA:
```bash
vault write auth/kubernetes/config \
    token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
    kubernetes_host="https://${KUBERNETES_PORT_443_TCP_ADDR}:443" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```
Then we create policy in .hcl file
```bash
path "secret/data/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/*" {
  capabilities = ["read", "list"]
}
```

Finally we create a role associated with policy. And this role can be used from any namespaces

```bash
vault write auth/kubernetes/role/vso-role \
    bound_service_account_names=vault-secrets-operator \
    bound_service_account_namespaces="*" \
    policies=vso-policy \
    ttl=24h
```
### Now we are going to deploy vault Vault Secrets Operator (VSO)
Add the Helm repo:

```bash
helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update
```
Install the operator:

```bash
kubectl create namespace vault-system

helm install vault-secrets-operator hashicorp/vault-secrets-operator \
  --namespace vault-system
```
Now we need to put secrets into vault for this we are going to create `secrets` kv and there create a secret named apiauth. then put secret there under key `db_url` and `jwt-secret` wwith required value. 
Now create a VaultAuth and Secret Sync CRD

```yaml
apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultAuth
metadata:
  name: vault-auth
  namespace: api-auth
spec:
  method: kubernetes
  mount: kubernetes
  kubernetes:
    role: vso-role
    serviceAccount: vault-secrets-operator
  vaultConnectionRef: vault-connection
---
apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultConnection
metadata:
  name: vault-connection
  namespace: api-auth
spec:
  address: "http://vault.vault.svc:8200"
  skipTLSVerify: true
---
apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultStaticSecret
metadata:
  name: postgrest-secret
  namespace: api-auth
spec:
  vaultAuthRef: vault-auth
  mount: secret
  type: kv-v2
  path: apiauth
  refreshAfter: 60s
  destination:
    create: true
    name: postgrest-secret-vault
```
Now apply this and we can see the secrets is populated
```bash
k get secrets -n api-auth
NAME                        TYPE                DATA   AGE
letsencrypt-postgrest       Opaque              1      14h
letsencrypt-postgrest-tls   kubernetes.io/tls   2      14h
postgres-credentials        Opaque              2      15h
postgrest-app-secrets       Opaque              2      14h
postgrest-secret-vault      Opaque              3      6s

❯ k describe -n api-auth secrets postgrest-secret-vault
Name:         postgrest-secret-vault
Namespace:    api-auth
Labels:       app.kubernetes.io/component=secret-sync
              app.kubernetes.io/managed-by=hashicorp-vso
              app.kubernetes.io/name=vault-secrets-operator
              secrets.hashicorp.com/vso-ownerRefUID=082931ae-789a-4cee-8d89-b7a7cee2fc9d
Annotations:  <none>

Type:  Opaque

Data
====
_raw:        3289 bytes
db_url:      63 bytes
jwt-secret:  2981 bytes

```


