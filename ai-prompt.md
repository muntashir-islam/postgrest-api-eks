1. "Describe the required PostgreSQL configuration change needed to switch a previously public-facing /products endpoint to be token-only access. Provide the necessary SQL command to revoke SELECT privileges from the web_anon role and explain why PostgREST returns a 401 Unauthorized error after this change."

2. "If the Vault Agent Sidecar fails to inject secrets, what specific error code or log message would I see in the vault-agent container? Explain the exact purpose of the bound_service_account_namespaces parameter in the Vault Kubernetes Auth role and why it prevents a Pod in the vault namespace from reading secrets intended for the api-auth namespace."
3. "have an Amazon EKS cluster currently using the default AWS VPC CNI plugin for pod networking. I want to migrate to Cilium CNI to leverage advanced features like eBPF networking, network policies, and encryption.

Please provide a step-by-step migration plan including:

Prerequisites and considerations before migration (like cluster version, node AMIs, pod CIDRs).

Installation steps for Cilium on EKS, including Helm deployment.

Configuration for multi-AZ and IP management, replacing aws-cni IPAM.

How to migrate existing workloads with zero downtime.

Validation steps to ensure pods are using Cilium networking and policies are applied.

Cleanup steps to remove aws-cni completely after migration.

Include Kubernetes manifests, Helm commands, and AWS-specific notes for EKS clusters."

4. "Analyze this logs and give me insights"
