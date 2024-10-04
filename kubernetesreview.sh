#!/bin/bash

echo -n "Enter your namespace [ENTER]: "
read namespace
echo

# Bold and Underlined text formatting
BOLD="\e[1m"
UNDERLINE="\e[4m"
RESET="\e[0m"

echo -e "${BOLD}Security Review for Namespace: ${namespace}${RESET}" | tee review-$namespace.txt

# Function to print an error message if the last command failed
check_error() {
    if [[ $? -ne 0 ]]; then
        echo -e "Error: Failed to execute the command" | tee -a review-$namespace.txt
    fi
}

#Get Kubernetes Version
echo -e "${BOLD}${UNDERLINE}Kubernetes and kubectl Version${RESET}" | tee -a review-$namespace.txt
kubectl version | tee -a review-$namespace.txt
check_error

# Check for Privileged Pods
# Privileged pods can access the host’s resources and pose a security risk. To find pods running with privileged containers:
echo -e "${BOLD}${UNDERLINE}Check for Privileged Pods${RESET}" | tee -a review-$namespace.txt
kubectl get pods --namespace $namespace -o json | jq '.items[] | select(.spec.containers[]?.securityContext?.privileged == true) | .metadata.name' | tee -a review-$namespace.txt
check_error

# Inspect Pod Security Contexts
# Security contexts define privilege and access control settings for a pod or container. Check if pods are running with restrictive security contexts:
echo -e "${BOLD}${UNDERLINE}Inspect Pod Security Contexts${RESET}" | tee -a review-$namespace.txt
kubectl get pods --namespace $namespace -o json | jq '.items[] | {pod: .metadata.name, namespace: .metadata.namespace, securityContext: .spec.containers[].securityContext}' | tee -a review-$namespace.txt
check_error

# Review Roles in the Namespace
# RBAC controls who can do what within the cluster. To list all roles and cluster roles:
echo -e "${BOLD}${UNDERLINE}Review Roles in the Namespace${RESET}" | tee -a review-$namespace.txt
kubectl get roles --namespace $namespace | tee -a review-$namespace.txt
check_error

# Review ClusterRoles
echo -e "${BOLD}${UNDERLINE}Review ClusterRoles${RESET}" | tee -a review-$namespace.txt
kubectl get clusterroles | tee -a review-$namespace.txt
check_error

# Review ClusterRoleBindings
echo -e "${BOLD}${UNDERLINE}Review ClusterRoleBindings${RESET}" | tee -a review-$namespace.txt
kubectl get clusterrolebindings | tee -a review-$namespace.txt
check_error

# Describe all Roles in the Namespace
echo -e "${BOLD}${UNDERLINE}Describe all Roles in the Namespace${RESET}" | tee -a review-$namespace.txt
kubectl describe role --namespace $namespace | tee -a review-$namespace.txt
check_error

# Describe all RoleBindings in the Namespace
echo -e "${BOLD}${UNDERLINE}Describe all RoleBindings in the Namespace${RESET}" | tee -a review-$namespace.txt
kubectl describe rolebinding --namespace $namespace | tee -a review-$namespace.txt
check_error

# Check for Anonymous Access
# Ensure that no resources are accessible anonymously:
echo -e "${BOLD}${UNDERLINE}Check for Anonymous Access${RESET}" | tee -a review-$namespace.txt
kubectl get clusterrolebinding | grep "system:anonymous" | tee -a review-$namespace.txt
check_error

# Inspect Service Accounts in the Namespace
# Each pod runs under a service account. Ensure that only necessary service accounts with minimal permissions are used:
echo -e "${BOLD}${UNDERLINE}Inspect Service Accounts in the Namespace${RESET}" | tee -a review-$namespace.txt
kubectl get serviceaccounts --namespace $namespace | tee -a review-$namespace.txt
check_error
kubectl describe serviceaccount --namespace $namespace | tee -a review-$namespace.txt
check_error

# Check for Insecure Secrets Management
# Kubernetes Secrets should be handled securely. List all secrets to review how they are managed:
echo -e "${BOLD}${UNDERLINE}Check for Insecure Secrets Management${RESET}" | tee -a review-$namespace.txt
kubectl get secrets --namespace $namespace | tee -a review-$namespace.txt
check_error
kubectl describe secret --namespace $namespace | tee -a review-$namespace.txt
check_error
# Note: This command only shows metadata, as the secret data is encoded. To decode the secret (for security reviews only), use:
# kubectl get secret <secret-name> -n <namespace> -o jsonpath="{.data.<key>}" | base64 --decode

# Audit Network Policies
# Ensure network policies are in place to restrict traffic between pods:
echo -e "${BOLD}${UNDERLINE}Audit Network Policies${RESET}" | tee -a review-$namespace.txt
kubectl get networkpolicies --namespace $namespace | tee -a review-$namespace.txt
check_error
kubectl describe networkpolicy --namespace $namespace | tee -a review-$namespace.txt
check_error

# Check for HostPath Volumes
# HostPath volumes can expose host directories to containers, which can be risky:
echo -e "${BOLD}${UNDERLINE}Review HostPath Volumes${RESET}" | tee -a review-$namespace.txt
kubectl get pods --namespace $namespace -o json | jq '.items[] | select(.spec.volumes[]?.hostPath) | .metadata.name' | tee -a review-$namespace.txt
check_error

# Review API Server Security Configurations
# Check the API server settings, which influence security. To review the running configuration:
echo -e "${BOLD}${UNDERLINE}Review API Server Security Configurations${RESET}" | tee -a review-$namespace.txt
kubectl get configmap kube-apiserver -n kube-system -o yaml | tee -a review-$namespace.txt
check_error

# Identify Pods Running as Root
# Pods running as root can be risky. Find pods running as the root user:
echo -e "${BOLD}${UNDERLINE}Identify Pods Running as Root${RESET}" | tee -a review-$namespace.txt
kubectl get pods --namespace $namespace -o json | jq '.items[] | select(.spec.containers[]?.securityContext?.runAsUser == 0) | .metadata.name' | tee -a review-$namespace.txt
check_error

# Inspect Pod Capabilities
# Review the capabilities assigned to containers within pods:
echo -e "${BOLD}${UNDERLINE}Inspect Pod Capabilities${RESET}" | tee -a review-$namespace.txt
kubectl get pods --namespace $namespace -o json | jq '.items[] | select(.spec.containers[]?.securityContext?.capabilities) | .metadata.name' | tee -a review-$namespace.txt
check_error

# Check Pods in kube-system Namespace
echo -e "${BOLD}${UNDERLINE}Check Pods in kube-system Namespace${RESET}" | tee -a review-$namespace.txt
kubectl get pods -n kube-system | tee -a review-$namespace.txt
check_error

# Review API Server Pods
# Admission controllers are crucial for security. Review their configuration by inspecting the API server:
echo -e "${BOLD}${UNDERLINE}Review API Server Pods${RESET}" | tee -a review-$namespace.txt
kubectl -n kube-system get pods | grep kube-apiserver | awk '{print $1}' | while read pod; do
    kubectl -n kube-system describe pod $pod | tee -a review-$namespace.txt
done
check_error

echo -e "${BOLD}Security review for namespace $namespace completed and saved to review-$namespace.txt${RESET}"