## Installing cilium for encrypting communication using wireguard and migratin aws vpc-cni

We can obiously do this using terrafom but as when I migrated cni all of my services was running in aws-cni mode. So I chose to setup cillium manually and replace aws-vpc-cni. This process has some downtime. 
we remove addons
```terrafom
addons = {
  coredns = {}
  eks-pod-identity-agent = {
    before_compute = true
  }
  kube-proxy = {} # <-- REMOVE
  vpc-cni = {     # <-- REMOVE
    before_compute = true
  }
}
=============>>
addons = {
  coredns = {}
  eks-pod-identity-agent = {
    before_compute = true
  }
}
```
Also we remove existing kubeproxy and aws-node(somehow its not replaced. Probably we need to replace nodegroup. So I did this)

```bash
kubectl delete ds -n kube-system kube-proxy
kubectl delete ds -n kube-system aws-node
# Both commands should return "Error from server (NotFound)"
kubectl get ds -n kube-system kube-proxy
kubectl get ds -n kube-system aws-node

Error from server (NotFound): daemonsets.apps "kube-proxy" not found
Error from server (NotFound): daemonsets.apps "aws-node" not found
```

and apply then terrafom config and add following helm charts
```bash
helm repo add cilium https://helm.cilium.io/
helm repo update
```
apply the cilium charts
```bash
EKS_CLUSTER_NAME="k8s-test" # Confirm this is the correct name
AWS_REGION="us-east-1"      # Must match the region in your Terraform
K8S_HOST=$(aws eks describe-cluster --name ${EKS_CLUSTER_NAME} --region ${AWS_REGION} --query "cluster.endpoint" --output text | sed 's|^https://||')

echo $K8S_HOST

helm install cilium cilium/cilium --version ${CILIUM_VERSION} \
  --namespace kube-system \
  --set eni.enabled=true \
  --set ipam.mode=eni \
  --set routingMode=native \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost=${K8S_HOST} \
  --set k8sServicePort=443 \
  --set encryption.enabled=true \
  --set encryption.type=wireguard \
  --set encryption.nodeEncryption=true \
  --set egressMasqueradeInterfaces=eth0 \
  --set operator.replicas=1 
```
verufy the deployment
```kubectl
k get pods -n kube-system

NAME                                            READY   STATUS    RESTARTS      AGE
cilium-envoy-8spt8                              1/1     Running   0             87m
cilium-envoy-hlb9z                              1/1     Running   0             87m
cilium-envoy-r8ttx                              1/1     Running   0             88m
cilium-operator-77b85d47d9-fkfnq                1/1     Running   0             88m
cilium-qk4q9                                    1/1     Running   0             87m
cilium-swth6                                    1/1     Running   0             87m
cilium-xnrsp                                    1/1     Running   0             88m
```
We also check encryption status for cilium

```bash
kubectl -n kube-system exec ds/cilium -- cilium-dbg status | grep -E "Encryption|KubeProxyReplacement"

KubeProxyReplacement:    True   [eth0   10.0.18.223 fe80::57:c9ff:fe92:4aa1 (Direct Routing), pod-id-link0    169.254.170.23 fd00:ec2::23 fe80::b4ab:15ff:fe45:21dd, eth1   10.0.29.98 fe80::d6:b2ff:fe26:7c43, eth2   10.0.31.240 fe80::36:adff:fe6b:f227]
Encryption:              Wireguard       [NodeEncryption: Enabled, cilium_wg0 (Pubkey: Eks3PpUisGSGZtffol0SM9YKqAJcgIww8PpHoQKVXEY=, Port: 51871, Peers: 2)]
```
After that we need to restart all deployment and statefullsets in all namespaces
```bash
kubectl rollout restart statefulsets
kubectl rollout restart deployment
```
Finally if you run cillium status you will see cilium cover all pods in all namespaces

```bash
cilium status
    /¯¯\
 /¯¯\__/¯¯\    Cilium:             OK
 \__/¯¯\__/    Operator:           OK
 /¯¯\__/¯¯\    Envoy DaemonSet:    OK
 \__/¯¯\__/    Hubble Relay:       disabled
    \__/       ClusterMesh:        disabled

DaemonSet              cilium                   Desired: 3, Ready: 3/3, Available: 3/3
DaemonSet              cilium-envoy             Desired: 3, Ready: 3/3, Available: 3/3
Deployment             cilium-operator          Desired: 1, Ready: 1/1, Available: 1/1
Containers:            cilium                   Running: 3
                       cilium-envoy             Running: 3
                       cilium-operator          Running: 1
                       clustermesh-apiserver    
                       hubble-relay             
Cluster Pods:          31/31 managed by Cilium
Helm chart version:    1.18.2
Image versions         cilium             quay.io/cilium/cilium:v1.18.2@sha256:858f807ea4e20e85e3ea3240a762e1f4b29f1cb5bbd0463b8aa77e7b097c0667: 3
                       cilium-envoy       quay.io/cilium/cilium-envoy:v1.34.7-1757592137-1a52bb680a956879722f48c591a2ca90f7791324@sha256:7932d656b63f6f866b6732099d33355184322123cfe1182e6f05175a3bc2e0e0: 3
                       cilium-operator    quay.io/cilium/operator-aws:v1.18.2@sha256:1cb856fbe265dfbcfe816bd6aa4acaf006ecbb22dcc989116a1a81bb269ea328: 1
```
## Installing ARGO cd and Deploy Postgrest-api
To install argocd following steps are taken
```yaml
kubectl create namespace argocd
kubectl apply -n argocd -f argocd/install.yaml
```
To access the ArgoCD UI, you need to forward the ArgoCD server port:

```bash
kubectl port-forward svc/argocd-server -n argocd 8080:443
```
The default username is admin, and to retrieve the password, use:
```bash
kubectl get secret argocd-initial-admin-secret -n argocd -o jsonpath={.data.password} | base64 -d
```

Then we connect our git repo from the setting and create a argocd application for postgrest-api application
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: kustomize-postgrest-api
  namespace: argocd
spec:
  destination:
    namespace: api-auth
    server: https://kubernetes.default.svc
  project: default
  source:
    path: deployments/postgrest-api
    repoURL: git@github.com:muntashir-islam/postgrest-api-eks.git
    targetRevision: HEAD
  syncPolicy:
    automated:
      selfHeal: true
```
here in deployments/postgrest-api we have postgrest deployment manifest managed by kustomize. This one is very simple one but in multi environment setup we keep these values into overlays and the provide patch from other environment folder like test, stage, production

```yaml
namePrefix: kustomize-

resources:
- deployment.yaml
- service.yaml
- ingress.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
```
for deployment we use vault generated secrets. Please check vault integration on the later part of the README. 
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgrest-api
  namespace: api-auth
  labels:
    app: postgrest
spec:
  replicas: 2
  selector:
    matchLabels:
      app: postgrest
  template:
    metadata:
      labels:
        app: postgrest
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchLabels:
                  app: postgrest
              topologyKey: "kubernetes.io/hostname"
      containers:
      - name: postgrest
        image: postgrest/postgrest:latest
        ports:
        - containerPort: 3000
        env:
          - name: PGRST_DB_URI
            valueFrom:
              secretKeyRef:
                name: postgrest-secret-vault
                key: db-uri
          - name: PGRST_JWT_SECRET
            valueFrom:
              secretKeyRef:
                name: postgrest-secret-vault
                key: jwt-secret
          - name: PGRST_JWT_ROLE_CLAIM_KEY # Keycloak role path from the article
            value: ".resource_access.postgrest_api.roles[0]"
          - name: PGRST_DB_AUTHENTICATOR_ROLE
            value: "authenticator"
          - name: PGRST_DB_ANON_ROLE
            value: "web_anon"
          - name: PGRST_DB_SCHEMAS
            value: "public" 
```
For ensuring high availability, we also use so that pod can span multiple az's node
```yaml
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchLabels:
                  app: postgrest
              topologyKey: "kubernetes.io/hostname"
```
antiAffinity pattern so the pod replica can span over all the nodes avaiable in cluster. For cost issue (keep node number limited otherwise karpenter create new nodes) we using `"kubernetes.io/hostname"` but in production environment we need to use `topologyKey: "topology.kubernetes.io/zone"` to ensure all pods are deployed multi az. For now all our node deployed in 2 azs so ensure HA and fault tolerence.

### Creating ingress and routing internet 

We also install ingress resource which bound with nginx-ingress controller
here is ingress resource mapping
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: prodapi-ingress
  namespace: api-auth
  annotations:
    cert-manager.io/issuer: letsencrypt-postgrest
    cert-manager.io/acme-challenge-type: http01
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/use-regex: "true"
    nginx.ingress.kubernetes.io/allow-headers: "true"
    
spec:
  ingressClassName: nginx
  rules:
    - host: api.muntashirislam.com
      http:
          paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: postgrest-service
                port:
                  number: 80
  tls:
  - hosts:
    -  api.muntashirislam.com
    secretName: letsencrypt-postgrest-tls
```

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

#later I created a initial  TABLES
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
Finally we put this base64 data into the deployment under the env variable `PGRST_JWT_SECRET` and also include other env variables here
```yaml
- name: PGRST_JWT_SECRET
  valueFrom:
    secretKeyRef:
      name: postgrest-secret-vault
      key: jwt-secret
- name: PGRST_JWT_ROLE_CLAIM_KEY # Keycloak role path
value: ".resource_access.postgrest_api.roles[0]"
- name: PGRST_DB_AUTHENTICATOR_ROLE
  value: "authenticator"
- name: PGRST_DB_ANON_ROLE
  value: "web_anon"
- name: PGRST_DB_SCHEMAS
  value: "public" 
```



now we can get the token from keycloak
```bash
ACCESS_TOKEN=$(
  curl -s --location 'https://oauth.muntashirislam.com/realms/my-postgrest-realm/protocol/openid-connect/token' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'client_id=postgrest-api' \
    --data-urlencode 'username=muntashir' \
    --data-urlencode 'password=admin321' \
    --data-urlencode 'grant_type=password' \
    --data-urlencode 'client_secret=<client-secret>' \
    | jq -r '.access_token'
)

echo "Extracted Token: $ACCESS_TOKEN"
```
Then you can call CURD operation on api

```bash
curl -i -X POST 'https://postgrest-api.muntashirislam.com/products' \
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
❯ curl -i -X POST 'https://postgrest-api.muntashirislam.com/products' \
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


