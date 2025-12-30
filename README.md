This repository demonstrates a robust, cost-optimized, and secure **Kubernetes architecture** designed for running production-grade workloads on AWS EKS. The primary application is a **PostgREST API** secured via Keycloak and HashiCorp Vault.

## 🌟 Key Features and Architectural Decisions

### Cloud & Compute Layer

* **Platform:** Deployed on **AWS EKS** with workloads running exclusively within **Private Subnets** for enhanced security.
* **Cluster Autoscaling:** We leverage **Karpenter** for dynamic and efficient scaling, utilizing a dedicated pool of **`m5.large`** instances (Spot and On-Demand) to optimize cost and resource provisioning speed.
* **Networking (Ingress):** Traffic enters via a dedicated **AWS Network Load Balancer (NLB)** in a public subnet, which routes to the internal **NGINX Ingress Controller**.
* **Cluster CNI and Network Security (Cilium):** **Cilium** is implemented with **WireGuard** enabled, providing secure, encrypted communication (encryption in transit) across all nodes in the cluster.

### Application & Security Layer

* **API Service (PostgREST):** The data API is powered by **PostgREST**, providing CRUD endpoints directly from the PostgreSQL database structure.
* **High Availability:** The **PostgREST API deployment** is configured with **Pod Anti-Affinity** across multiple Availability Zones (AZs) and nodes, ensuring the service remains available during node failures.
* **Database:** A single-replica **PostgreSQL** database is deployed within Kubernetes to minimize infrastructure costs while providing necessary persistence.
* **Authentication & Authorization:**
    * **Authentication (AuthN):** Handled externally by **Keycloak** (OIDC), issuing digitally signed JWTs.
    * **Authorization (AuthZ):** Enforced by **PostgREST** and PostgreSQL's powerful **Role-Level Security (RLS)** based on claims extracted from the JWT.
* **Secret Management:** All sensitive configuration—including the DB URI, Keycloak JWKS endpoint, and credentials—is managed by **HashiCorp Vault** using the **Vault Secret Operator** for secure, dynamic secret delivery.
* **TLS/SSL:** **Cert-Manager** automatically provisions and manages TLS certificates for all exposed application endpoints.

### Observability

* **Logging:** Logs are collected cluster-wide by **Filebeat** and pushed centrally to an **Elasticsearch** cluster.
* **Metrics:** Metrics are collected and stored in **Prometheus** for performance monitoring and alerting.

### Scaling and Deployment

* **Application Autoscaling (PostgREST API):** **Horizontal Pod Autoscaler (HPA)** is deployed to scale the PostgREST API workload up to **5 replicas**, tracking **CPU utilization** as the primary metric.
* **Deployment Method:** The entire PostgREST API lifecycle (deployment, scaling, configuration) follows a **GitOps approach** using **ArgoCD**.


## 🚀 Application Architecture Summary

The architecture creates a secure data API by separating **Authentication** (handled by Keycloak and NGINX) from **Authorization** (enforced by PostgREST and PostgreSQL).

| Component | Technology | Role |
| :--- | :--- | :--- |
| **API Gateway** | **NGINX Ingress** | Routes traffic (`postgrest-api.muntashirislam.com`) and enforces **Authentication** using the external JWT Validator pattern. |
| **Identity Provider** | **Keycloak** (`oauth.muntashirislam.com`) | Issues signed **JWTs (RS256)** via the Password Grant flow. Provides the public key via the **JWKS endpoint** for validation. |
| **Secret Management** | **HashiCorp Vault** | Securely stores and injects sensitive configuration (DB connection string, JWKS URL) into the PostgREST Pod using the **Vault Secret Operator**. |
| **API Backend** | **PostgREST** | Validates the JWT, extracts the **`role` claim**, and executes requests by impersonating a secure PostgreSQL role. |
| **Data Layer** | **PostgreSQL** | Enforces all **Authorization** rules via role permissions and **Row-Level Security (RLS)**. |

***
## 🛡️ Key Security and Authorization Configurations

The security framework relies on the following configurations:

### 1. Token Validation (PostgREST Configuration)

PostgREST is configured for **Asymmetric JWT Verification** (RS256) by specifying the remote public key endpoint.

* **Configuration Parameter:** `PGRST_JWT_SECRET`
* **Value (Injected from Vault):** `@https://oauth.muntashirislam.com/realms/my-postgrest-realm/protocol/openid-connect/certs`
    *(The `@` prefix instructs PostgREST to fetch the Keycloak public key from this JWKS endpoint.)*

### 2. Role-Based Authorization (PostgreSQL)

Authorization is managed by three PostgreSQL roles:

| Role Name | Access Level | PostgREST Config |
| :--- | :--- | :--- |
| **`authenticator`** | **Privileged DB Connector.** Used by PostgREST to connect and switch roles. | `PGRST_DB_AUTHENTICATOR_ROLE` |
| **`inventory_user`** | **Authenticated User.** Granted `SELECT`, `INSERT`, `UPDATE`, `DELETE` on exposed objects (e.g., `products`). | Mapped via JWT claim. |
| **`web_anon`** | **Anonymous User.** **Access REVOKED.** Has no `SELECT` privileges on tables/views, enforcing a mandatory JWT for all data access. | `PGRST_DB_ANON_ROLE` |

### 3. Secret Management (Vault)
* Utilizing vault secret operator(vso)
* **Secrets Path:** `secret/apiauth`
* **K8s Role:** `vso-role` (Bound to the `vault-secrets-operator` Service Account in the `api-auth` namespace).
* **Injection:** The **Vault VaultStaticSecret CRD** fetches necessary secrets and exposes them as secrets variables mounted as env inside the DB and PostgREST application container.

***

## ⚙️ How to Test the API

Assuming the deployment is running and your environment variable `$ACCESS_TOKEN` is set with a valid token for the `inventory_user`:

### 1. Anonymous Access (Expected Failure)

All attempts without a token should fail, confirming security is enforced:

```bash
curl -i '[https://postgrest-api.muntashirislam.com/products](https://postgrest-api.muntashirislam.com/products)'
# EXPECTED: 401 Unauthorized
```

### 1. Authenticated CRUD Operation (Success)

A request with a valid token should successfully create a resource:
```bash
ACCESS_TOKEN=$(
  curl -s --location 'https://oauth.muntashirislam.com/realms/my-postgrest-realm/protocol/openid-connect/token' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'client_id=postgrest_api' \
    --data-urlencode 'username=muntashir' \
    --data-urlencode 'password=admin321' \
    --data-urlencode 'grant_type=password' \
    --data-urlencode 'client_secret=W043cYReKtTVMeBkLl6KAYZFX4cEcTlS' \
    | jq -r '.access_token'
)
curl -i  -H "Authorization: Bearer $ACCESS_TOKEN" 'https://postgrest-api.muntashirislam.com/products'
HTTP/2 200 
date: Mon, 13 Oct 2025 13:43:01 GMT
content-type: application/json; charset=utf-8
content-length: 549
content-range: 0-4/*
content-location: /products
strict-transport-security: max-age=31536000; includeSubDomains

[{"product_id":1,"product_name":"Test Product2","price":200,"description":"Auth Test 2"}, 
 {"product_id":2,"product_name":"Test Product3","price":300,"description":"Auth Test 3"}, 
 {"product_id":3,"product_name":"Premium Keyboard","price":129.99,"description":"Mechanical keyboard with brown switches."}, 
 {"product_id":4,"product_name":"Wireless Mouse","price":49.50,"description":"Ergonomic gaming mouse, RGB lighting."}, 
 {"product_id":5,"product_name":"4K Monitor","price":499.00,"description":"27-inch 4K monitor with 144Hz refresh rate."}]   
```
If you want to test kaycloak then url is `https://oauth.muntashirislam.com/` password: `admin/admin321$`
## Overall Cluster preparation Procedure

Navigate to the iac directory and run `terraform apply`. This command will create all required resources and deploy the necessary Helm charts for components such as the CSI driver, LoadBalancer, Node Identity, Karpenter, and others. The cluster is initially set up using the AWS VPC-CNI, which can later be replaced with a different CNI plugin if needed.
Next, apply the Karpenter NodePool configuration.
```yaml
---
apiVersion: karpenter.k8s.aws/v1
kind: EC2NodeClass
metadata:
  name: default
spec:
  amiSelectorTerms:
    - alias: bottlerocket@latest
  role: k8s-test
  subnetSelectorTerms:
    - tags:
        karpenter.sh/discovery: k8s-test
  securityGroupSelectorTerms:
    - tags:
        karpenter.sh/discovery: k8s-test
  tags:
    karpenter.sh/discovery: k8s-test
---
apiVersion: karpenter.sh/v1
kind: NodePool
metadata:
  name: default
spec:
  template:
    spec:
      nodeClassRef:
        group: karpenter.k8s.aws
        kind: EC2NodeClass
        name: default
      requirements:
        - key: kubernetes.io/arch
          operator: In
          values: ["amd64"]
        - key: kubernetes.io/os
          operator: In
          values: ["linux"]
        - key: karpenter.sh/capacity-type
          operator: In
          values: ["spot", "on-demand"]
        - key: node.kubernetes.io/instance-type
          operator: In
          values: ["m5.large"]
  limits:
    cpu: 20
  disruption:
    consolidationPolicy: WhenEmpty
    consolidateAfter: 30s
```
### Installing Cilium CNI
For installing cilium cni we do following steps
1. **Update Terraform Addons** 

Remove kube-proxy and vpc-cni from your Terraform configuration and run `terraform apply`:

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
2. **Remove Existing DaemonSets**

Delete the default kube-proxy and aws-node DaemonSets:

```bash
kubectl delete ds -n kube-system kube-proxy
kubectl delete ds -n kube-system aws-node
# Both commands should return "Error from server (NotFound)"
kubectl get ds -n kube-system kube-proxy
kubectl get ds -n kube-system aws-node

Error from server (NotFound): daemonsets.apps "kube-proxy" not found
Error from server (NotFound): daemonsets.apps "aws-node" not found
```

3. **Install Cilium via Helm**
Add and update the Cilium Helm repository:
```bash
helm repo add cilium https://helm.cilium.io/
helm repo update
```
Install Cilium:
```bash
EKS_CLUSTER_NAME="k8s-test" 
AWS_REGION="us-east-1" 
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
4. **Verify Cilium Deployment**

  Check pods in `kube-system` namespace:

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
 Check Cilium encryption and kube-proxy replacement status:

```bash
kubectl -n kube-system exec ds/cilium -- cilium-dbg status | grep -E "Encryption|KubeProxyReplacement"

KubeProxyReplacement:    True   [eth0   10.0.18.223 fe80::57:c9ff:fe92:4aa1 (Direct Routing), pod-id-link0    169.254.170.23 fd00:ec2::23 fe80::b4ab:15ff:fe45:21dd, eth1   10.0.29.98 fe80::d6:b2ff:fe26:7c43, eth2   10.0.31.240 fe80::36:adff:fe6b:f227]
Encryption:              Wireguard       [NodeEncryption: Enabled, cilium_wg0 (Pubkey: Eks3PpUisGSGZtffol0SM9YKqAJcgIww8PpHoQKVXEY=, Port: 51871, Peers: 2)]
```
5. Restart All Deployments and StatefulSets in all namespaces
```bash
kubectl rollout restart statefulsets
kubectl rollout restart deployment
```
Finally confirm Cilium Coverage

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

### Installing HashiCorp Vault to securely manage all secret data.

We will install Vault to securely store all the necessary secrets required for our application deployments. Begin by preparing the configuration values for the Vault Helm chart in a vault-values.yaml file.

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
Installing the Vault Helm chart.

```bash
helm repo add hashicorp https://helm.releases.hashicorp.com
helm install vault hashicorp/vault --namespace vault -f vault-values.yaml
```

At this stage, the Vault pods should be running, but they will be in an unsealed state.

```bash
k get pods -n vault

NAME                                    READY   STATUS    RESTARTS   AGE
vault-0                                 0/1     Running   0          3m28s
vault-agent-injector-556c5dd8fb-wcdtk   1/1     Running   0          3m28s
```
We will now initialize Vault. (The following example uses demo data.)

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

After running these commands, Vault should now be in a running state.

```bash
k get pods -n vault

NAME                                    READY   STATUS    RESTARTS   AGE
vault-0                                 1/1     Running   0          12m
vault-agent-injector-556c5dd8fb-wcdtk   1/1     Running   0          12m
```

Next, we need to configure Vault for use with the Kubernetes Secret Store CSI driver. The following steps outline the required setup:

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
Configure Vault to use your Kubernetes cluster’s service account JWT and CA certificate:

```bash
vault write auth/kubernetes/config \
    token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
    kubernetes_host="https://${KUBERNETES_PORT_443_TCP_ADDR}:443" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```
Next, create a Vault policy in an .hcl file.

```bash
path "secret/data/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/*" {
  capabilities = ["read", "list"]
}
```

Finally, create a Vault role and associate it with the policy. This role can be accessed from any namespace within the cluster.

```bash
vault write auth/kubernetes/role/vso-role \
    bound_service_account_names=vault-secrets-operator \
    bound_service_account_namespaces="*" \
    policies=vso-policy \
    ttl=24h
```
### Deploying the Vault Secrets Operator (VSO).

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
Next, we will add secrets to Vault. Follow these steps:

1. Create a KV secrets engine called `secret`.

2. Within secrets, create a secret named `apiauth`.

3. Add keys `db-uri` and `jwt-secret` with their respective values.(This will be used later deploying `Postgrest-API` application)


<img width="1171" height="432" alt="image" src="https://github.com/user-attachments/assets/d077931e-fb6e-4d83-a5e0-28c59f4807dc" />
<img width="1171" height="432" alt="image" src="https://github.com/user-attachments/assets/a333b834-9bb8-448c-b730-6b86b5fd3ce7" />
4. Create a VaultAuth and SecretSync Custom Resource Definition (CRD) to enable Kubernetes access to these secrets.

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
  path: postgres
  refreshAfter: 60s
  destination:
    create: true
    name: postgres-secret-vault
---
apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultStaticSecret
metadata:
  name: postgrest-api-secret
  namespace: api-auth
spec:
  vaultAuthRef: vault-auth   # VaultAuth must exist in vault-system
  mount: secret
  type: kv-v2
  path: apiauth
  refreshAfter: 60s
  destination:
    create: true
    name: postgrest-api-secret-vault
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
db-uri:      63 bytes
jwt-secret:  2981 bytes

```
We will use this secret later during api deployment 
## Deploying Keycloak in keycloak namespace
We will now deploy Keycloak using the manifests available in `deployments/keycloak`. This includes deploying both the PostgreSQL database and the Keycloak application itself.
```bash
kubectl apply -f deployments/kaycloak/postgres.yaml
kubectl apply -f deployments/kaycloak/keycloak.yaml
```
Here
1. Secrets are managed by vault
2. Keycloak is exposed on `https://oauth.muntashirislam.com`

Below are some snapshots taken during the Keycloak configuration process.
<img width="1777" height="764" alt="image" src="https://github.com/user-attachments/assets/da34b9ef-dfce-41cd-ab3c-0f3c761ab531" />
<img width="1790" height="453" alt="image" src="https://github.com/user-attachments/assets/5a23b41b-c19d-4463-a332-b6cbe96188b2" />
<img width="1790" height="876" alt="image" src="https://github.com/user-attachments/assets/2cf236a2-ca27-436c-a9dc-a120d533a9ee" />

## Integrate JWT token based authentication for Postgrest API
First, deploy the PostgreSQL database into the api-auth namespace.
```bash
kubectl apply -f deployments/postgres-db/postgres.yaml
```
Ensure that the PostgreSQL pod is running. In our case, the api-auth namespace contains a running PostgreSQL database.

```yaml
kubectl get pods -n api-auth

NAME                             READY   STATUS    RESTARTS   AGE
postgres-6748f9856c-pnz8r        1/1     Running   0          118m
```
If you want PostgreSQL need to be HA with number of relica then use CNPG operator here instead of single instance setup

```bash
kubectl apply --server-side -f \
  https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.28/releases/cnpg-1.28.0.yaml
```
Then apply the postgres-with-cnpg.yaml file

```bash
kubectl get all -n api-auth 
NAME                 READY   STATUS    RESTARTS   AGE
pod/app-postgres-1   1/1     Running   0          47s
pod/app-postgres-2   1/1     Running   0          28s

NAME                      TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
service/app-postgres-r    ClusterIP   10.96.215.37    <none>        5432/TCP   73s
service/app-postgres-ro   ClusterIP   10.96.253.235   <none>        5432/TCP   73s
service/app-postgres-rw   ClusterIP   10.96.121.151   <none>        5432/TCP   73s
```

Next, run the following script to create the necessary roles for JWT authentication. 
If you use multi node pg then 
```bash
kubectl port-forward -n pg svc/app-postgres-rw 5432:5432
psql -h localhost -U app_user -d app_db
```

if it is single node pg then do following
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

To revoke access for anonymous users from viewing a table, run the following command(did this):

```bash
REVOKE SELECT ON public.products FROM web_anon;
``` 

We have now deployed Keycloak and exposed it via an Ingress. In this example, the URL is `https://oauth.muntashirislam.com`. Note: In a production setup, Keycloak should be exposed as a ClusterIP service instead of using an external Ingress. Next, follow these steps to configure the Keycloak service from the Keycloak console:

- Navigate to https://auth.muntashirislam.com/admin.

- Create Realm (e.g., my-postgrest-realm).

- Create Client (Client ID: postgrest_api, Client authentication: on).

- Credentials Tab: Note the Client Secret.

- Roles Tab: Create Realm Roles: web_user, inventory_user.

- Client Scopes: Ensure your roles are mapped to the access token under the JSON path: .resource_access.postgrest_api.roles.

- Map user (muntashir/admin321) with the role

Now we also need JWKS endpoint for the authentication

```bash
curl -sS https://oauth.muntashirislam.com/realms/my-postgrest-realm/protocol/openid-connect/certs > keycloak-jwks.json
cat keycloak-jwks.json | base64

```
Finally, encode the secret as Base64 and add it to your deployment under the environment variable PGRST_JWT_SECRET. Be sure to include any other required environment variables as well.
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
    --data-urlencode 'client_id=postgrest_api' \
    --data-urlencode 'username=muntashir' \
    --data-urlencode 'password=admin321' \
    --data-urlencode 'grant_type=password' \
    --data-urlencode 'client_secret=W043cYReKtTVMeBkLl6KAYZFX4cEcTlS' \
    | jq -r '.access_token'
)

echo "Extracted Token: $ACCESS_TOKEN"
```
You can now perform CRUD operations on the API.

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

#Another Example
curl -i -X POST 'https://postgrest-api.muntashirislam.com/products' -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" -H "Prefer: return=representation" -d '[{"product_name":"Premium Keyboard","price":129.99,"description":"Mechanical keyboard with brown switches."},{"product_name":"Wireless Mouse","price":49.50,"description":"Ergonomic gaming mouse, RGB lighting."},{"product_name":"4K Monitor","price":499.00,"description":"27-inch 4K monitor with 144Hz refresh rate."}]'
``` 
However, if you want to perform this operation without using a Keycloak token, follow these steps:

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
This setup will work once the PostgREST API is deployed and running.
## Installing ARGO cd and Deploy Postgrest-api
The following steps are used to install ArgoCD:
```yaml
kubectl create namespace argocd
kubectl apply -n argocd -f argocd/install.yaml
```
To access the ArgoCD UI, forward the ArgoCD server port using the following command:

```bash
kubectl port-forward svc/argocd-server -n argocd 8080:443
```
The default username is admin. Retrieve the initial password with:
```bash
kubectl get secret argocd-initial-admin-secret -n argocd -o jsonpath={.data.password} | base64 -d
```

Next, connect your Git repository via the ArgoCD settings and create an ArgoCD application for the postgrest-api service.
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
In deployments/postgrest-api, we have the PostgREST deployment manifest managed using Kustomize. This example is simple, but in a multi-environment setup, we store environment-specific values in overlays and apply patches from folders such as test, stage, or production.
<img width="1619" height="929" alt="image" src="https://github.com/user-attachments/assets/b85e8704-74cb-4aee-be15-3011a60cd40e" />

```yaml
resources:
- deployment.yaml
- service.yaml
- ingress.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
```
Here is the postgrest-api deployment
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
To ensure high availability, we configure the deployment so that pods can be scheduled across nodes in multiple Availability Zones (AZs).
```yaml
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchLabels:
                  app: postgrest
              topologyKey: "kubernetes.io/hostname"
```
We use an anti-affinity pattern to ensure that pod replicas are distributed across all available nodes in the cluster. For cost considerations (to limit the number of nodes and avoid unnecessary Karpenter node provisioning), we currently use: `kubernetes.io/hostname`. In a production environment, it’s recommended to use: `topologyKey: "topology.kubernetes.io/zone"`

This ensures that pods are deployed across multiple Availability Zones (AZs), providing true high availability and fault tolerance. In our current setup, all nodes are deployed across 2 AZs, which satisfies basic HA and fault-tolerance requirements.

### Creating ingress and routing internet 

We also deploy an Ingress resource, which is associated with the NGINX Ingress Controller. Below is the mapping for the Ingress resource:

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
    - host: postgrest-api.muntashirislam.com
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
    -  postgrest-api.muntashirislam.com
    secretName: letsencrypt-postgrest-tls
```
A simple HPA also added in the deployment
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: postgrest-api-hpa
  namespace: api-auth 
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: postgrest-api
  minReplicas: 2
  maxReplicas: 5
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 80
```
## Monitoring and Logging

For monitoring, we will deploy the Prometheus and Grafana stack using Helm charts.

```bash
helm install prometheus prometheus-community/prometheus \
  --namespace monitoring \
  --set alertmanager.enabled=false \
  --set server.persistentVolume.enabled=true \
  --set server.persistentVolume.storageClass=gp2 \
  --set server.persistentVolume.size=2G

helm install grafana grafana/grafana \
  --namespace monitoring \
  --set adminUser=admin \
  --set adminPassword=admin321

k get all -n monitoring

NAME                                                     READY   STATUS    RESTARTS   AGE
pod/grafana-847755c5b8-8wtxd                             1/1     Running   0          10h
pod/prometheus-kube-state-metrics-d4fd85895-g6hq5        1/1     Running   0          10h
pod/prometheus-prometheus-node-exporter-9jv96            1/1     Running   0          10h
pod/prometheus-prometheus-node-exporter-jmjn5            1/1     Running   0          10h
pod/prometheus-prometheus-node-exporter-v772j            1/1     Running   0          10h
pod/prometheus-prometheus-pushgateway-65ddfcc6c4-dgnmk   1/1     Running   0          10h
pod/prometheus-server-5c6cdd5d7-fh5b5                    2/2     Running   0          10h

NAME                                          TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)    AGE
service/grafana                               ClusterIP   172.20.146.171   <none>        80/TCP     10h
service/prometheus-kube-state-metrics         ClusterIP   172.20.90.5      <none>        8080/TCP   10h
service/prometheus-prometheus-node-exporter   ClusterIP   172.20.118.34    <none>        9100/TCP   10h
service/prometheus-prometheus-pushgateway     ClusterIP   172.20.32.157    <none>        9091/TCP   10h
service/prometheus-server                     ClusterIP   172.20.88.74     <none>        80/TCP     10h

NAME                                                 DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR            AGE
daemonset.apps/prometheus-prometheus-node-exporter   3         3         3       3            3           kubernetes.io/os=linux   10h

NAME                                                READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/grafana                             1/1     1            1           10h
deployment.apps/prometheus-kube-state-metrics       1/1     1            1           10h
deployment.apps/prometheus-prometheus-pushgateway   1/1     1            1           10h
deployment.apps/prometheus-server                   1/1     1            1           10h

NAME                                                           DESIRED   CURRENT   READY   AGE
replicaset.apps/grafana-847755c5b8                             1         1         1       10h
replicaset.apps/prometheus-kube-state-metrics-d4fd85895        1         1         1       10h
replicaset.apps/prometheus-prometheus-pushgateway-65ddfcc6c4   1         1         1       10h
replicaset.apps/prometheus-server-5c6cdd5d7                    1         1         1       10h
```
<img width="1487" height="975" alt="image" src="https://github.com/user-attachments/assets/1a92ae8b-ae43-4fd9-929d-e66e0ab9d355" />

Grafana is deployed in a stateless configuration for simplicity in this setup.

For logging, we deploy a simple custom setup using the manifests available in the `monitoring/logging` directory.
```bash
k get all -n log
NAME                                 READY   STATUS    RESTARTS   AGE
pod/elasticsearch-6b5b84567b-24zrr   1/1     Running   0          3h39m
pod/filebeat-8t55p                   1/1     Running   0          107m
pod/filebeat-ktdj6                   1/1     Running   0          107m
pod/filebeat-phjfl                   1/1     Running   0          107m
pod/kibana-6fd4dc4968-gpqpl          1/1     Running   0          3h37m

NAME                    TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)    AGE
service/elasticsearch   ClusterIP   172.20.105.236   <none>        9200/TCP   3h46m
service/kibana          ClusterIP   172.20.102.248   <none>        5601/TCP   3h37m

NAME                      DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR   AGE
daemonset.apps/filebeat   3         3         3       3            3           <none>          108m

NAME                            READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/elasticsearch   1/1     1            1           3h46m
deployment.apps/kibana          1/1     1            1           3h37m

NAME                                       DESIRED   CURRENT   READY   AGE
replicaset.apps/elasticsearch-57cc9dcdf6   0         0         0       3h46m
replicaset.apps/elasticsearch-6b5b84567b   1         1         1       3h39m
replicaset.apps/elasticsearch-868675f46b   0         0         0       3h41m
replicaset.apps/kibana-6fd4dc4968          1         1         1       3h37m
```
<img width="1624" height="1022" alt="image" src="https://github.com/user-attachments/assets/41ce4e04-ac7c-44f5-b5ab-edb6e97afa27" />
Logging and metrics endpoint are not exposed internet.

## Improvements

There are several enhancements we can make to this stack to improve availability, security, and performance. Some of the key improvements include:

1. **High Availability Across AZs/Zones**  
   Ensure all deployments are highly available by spanning pods across multiple Availability Zones or even regions to improve fault tolerance.

2. **Security Contexts for Applications**  
   Apply Kubernetes security contexts and Pod Security Standards for all applications to enforce least-privilege access and mitigate risks.

3. **Enhanced PostgREST API Security**  
   Use Keycloak more extensively to control API access, implement fine-grained RBAC, and secure endpoints with OAuth2/JWT policies.

4. **Optimized Node Pools with Karpenter**  
   Use Karpenter to automatically scale and optimize node pools based on workload demand, reducing cost and improving efficiency.

5. **Persistent Grafana and Prometheus Storage**  
   Configure persistent storage for monitoring stack to retain metrics and dashboards across pod restarts.

6. **CI/CD Integration with ArgoCD**  
   Automate deployments across environments (dev, test, stage, production) using GitOps best practices and ArgoCD. Cover all deployment under argo. 

7. **Resource Limits and Requests**  
   Define proper CPU/memory requests and limits for all workloads to prevent resource contention and ensure cluster stability.

8. **Network Policies**  
   Apply Kubernetes NetworkPolicies to restrict traffic between pods and services, enhancing security and reducing attack surface.

9. **Secret Management Best Practices**  
    Leverage HashiCorp Vault more robustly by enabling automatic secret rotation and avoiding hardcoded credentials in applications.
   


