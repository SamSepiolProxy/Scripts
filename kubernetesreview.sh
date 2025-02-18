#!/bin/bash

echo -n "Enter your namespace [ENTER]: "
read namespace
echo

# Create output folder and combined output file
output_folder="review-${namespace}"
mkdir -p "$output_folder"
combined_file="${output_folder}/combined.txt"
> "$combined_file"  # clear combined file

# Bold and Underlined text formatting
BOLD="\e[1m"
UNDERLINE="\e[4m"
RESET="\e[0m"

# Function to print an error message if the last command failed
check_error() {
    if [[ $? -ne 0 ]]; then
        echo -e "Error: Failed to execute the command" | tee -a "$combined_file"
    fi
}

# Section 1: Kubernetes and kubectl Version
section_file="${output_folder}/k8s_version.txt"
echo -e "${BOLD}${UNDERLINE}Kubernetes and kubectl Version${RESET}" | tee -a "$section_file" "$combined_file"
kubectl version | tee -a "$section_file" "$combined_file"
check_error

# Section 2: Check for Privileged Pods
section_file="${output_folder}/privileged_pods.txt"
echo -e "${BOLD}${UNDERLINE}Check for Privileged Pods${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get pods --namespace "$namespace" -o json | jq '.items[] | select(.spec.containers[]?.securityContext?.privileged == true) | .metadata.name' | tee -a "$section_file" "$combined_file"
check_error

# Section 3: Inspect Pod Security Contexts
section_file="${output_folder}/pod_security_contexts.txt"
echo -e "${BOLD}${UNDERLINE}Inspect Pod Security Contexts${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get pods --namespace "$namespace" -o json | jq '.items[] | {pod: .metadata.name, namespace: .metadata.namespace, securityContext: .spec.containers[].securityContext}' | tee -a "$section_file" "$combined_file"
check_error

# Section 4: Check for runAsGroup Setting
section_file="${output_folder}/runAsGroup.txt"
echo -e "${BOLD}${UNDERLINE}Check Pod runAsGroup Setting${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get pods --namespace "$namespace" -o json | jq '.items[] | {pod: .metadata.name, runAsGroup: .spec.containers[].securityContext.runAsGroup}' | tee -a "$section_file" "$combined_file"
check_error

# Section 5: Check for runAsUser Setting
section_file="${output_folder}/runAsUser.txt"
echo -e "${BOLD}${UNDERLINE}Check Pod runAsUser Setting${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get pods --namespace "$namespace" -o json | jq '.items[] | {pod: .metadata.name, runAsUser: .spec.containers[].securityContext.runAsUser}' | tee -a "$section_file" "$combined_file"
check_error

# Section 6: Check for runAsNonRoot Setting
section_file="${output_folder}/runAsNonRoot.txt"
echo -e "${BOLD}${UNDERLINE}Check Pod runAsNonRoot Setting${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get pods --namespace "$namespace" -o json | jq '.items[] | {pod: .metadata.name, runAsNonRoot: .spec.containers[].securityContext.runAsNonRoot}' | tee -a "$section_file" "$combined_file"
check_error

# Section 7: Check for allowPrivilegeEscalation Setting
section_file="${output_folder}/allowPrivilegeEscalation.txt"
echo -e "${BOLD}${UNDERLINE}Check Pod allowPrivilegeEscalation Setting${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get pods --namespace "$namespace" -o json | jq '.items[] | {pod: .metadata.name, allowPrivilegeEscalation: .spec.containers[].securityContext.allowPrivilegeEscalation}' | tee -a "$section_file" "$combined_file"
check_error

# Section 8: Review Roles in the Namespace
section_file="${output_folder}/roles.txt"
echo -e "${BOLD}${UNDERLINE}Review Roles in the Namespace${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get roles --namespace "$namespace" | tee -a "$section_file" "$combined_file"
check_error

# Section 9: Review ClusterRoles
section_file="${output_folder}/clusterroles.txt"
echo -e "${BOLD}${UNDERLINE}Review ClusterRoles${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get clusterroles --namespace "$namespace" | tee -a "$section_file" "$combined_file"
check_error

# Section 10: Review ClusterRoleBindings
section_file="${output_folder}/clusterrolebindings.txt"
echo -e "${BOLD}${UNDERLINE}Review ClusterRoleBindings${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get clusterrolebindings --namespace "$namespace" | tee -a "$section_file" "$combined_file"
check_error

# Section 11: Describe all Roles in the Namespace
section_file="${output_folder}/describe_roles.txt"
echo -e "${BOLD}${UNDERLINE}Describe all Roles in the Namespace${RESET}" | tee -a "$section_file" "$combined_file"
kubectl describe role --namespace "$namespace" | tee -a "$section_file" "$combined_file"
check_error

# Section 12: Get Role Definitions in the Namespace
section_file="${output_folder}/role_definitions.txt"
echo -e "${BOLD}${UNDERLINE}Get Role Definitions in the Namespace${RESET}" | tee -a "$section_file" "$combined_file"
roles=$(kubectl get roles --namespace "$namespace" -o jsonpath='{.items[*].metadata.name}')
for role in $roles; do
    echo -e "${BOLD}Definition for Role: ${role}${RESET}" | tee -a "$section_file" "$combined_file"
    kubectl get role "${role}" --namespace "$namespace" -o yaml | tee -a "$section_file" "$combined_file"
    check_error
    echo -e "\n" | tee -a "$section_file" "$combined_file"
done

# Section 13: Describe all RoleBindings in the Namespace
section_file="${output_folder}/describe_rolebindings.txt"
echo -e "${BOLD}${UNDERLINE}Describe all RoleBindings in the Namespace${RESET}" | tee -a "$section_file" "$combined_file"
kubectl describe rolebinding --namespace "$namespace" | tee -a "$section_file" "$combined_file"
check_error

# Section 14: Check for Anonymous Access
section_file="${output_folder}/anonymous_access.txt"
echo -e "${BOLD}${UNDERLINE}Check for Anonymous Access${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get clusterrolebinding | grep "system:anonymous" | tee -a "$section_file" "$combined_file"
check_error

# Section 15: Inspect Service Accounts in the Namespace
section_file="${output_folder}/serviceaccounts.txt"
echo -e "${BOLD}${UNDERLINE}Inspect Service Accounts in the Namespace${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get serviceaccounts --namespace "$namespace" | tee -a "$section_file" "$combined_file"
check_error
kubectl describe serviceaccount --namespace "$namespace" | tee -a "$section_file" "$combined_file"
check_error

# Section 16: Check for Insecure Secrets Management
section_file="${output_folder}/secrets.txt"
echo -e "${BOLD}${UNDERLINE}Check for Insecure Secrets Management${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get secrets --namespace "$namespace" | tee -a "$section_file" "$combined_file"
check_error
kubectl describe secret --namespace "$namespace" | tee -a "$section_file" "$combined_file"
check_error
echo -e "# Note: Secret data is base64 encoded. To decode, use:\n# kubectl get secret <secret-name> -n <namespace> -o jsonpath=\"{.data.<key>}\" | base64 --decode" | tee -a "$section_file" "$combined_file"

# Section 17: Audit Network Policies
section_file="${output_folder}/network_policies.txt"
echo -e "${BOLD}${UNDERLINE}Audit Network Policies${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get networkpolicies --namespace "$namespace" | tee -a "$section_file" "$combined_file"
check_error
kubectl describe networkpolicy --namespace "$namespace" | tee -a "$section_file" "$combined_file"
check_error

# Section 18: Check for HostPath Volumes
section_file="${output_folder}/hostpath_volumes.txt"
echo -e "${BOLD}${UNDERLINE}Review HostPath Volumes${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get pods --namespace "$namespace" -o json | jq '.items[] | select(.spec.volumes[]?.hostPath) | .metadata.name' | tee -a "$section_file" "$combined_file"
check_error

# Section 19: Review API Server Security Configurations
section_file="${output_folder}/apiserver_config.txt"
echo -e "${BOLD}${UNDERLINE}Review API Server Security Configurations${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get configmap kube-apiserver -n kube-system -o yaml | tee -a "$section_file" "$combined_file"
check_error

# Section 20: Identify Pods Running as Root
section_file="${output_folder}/pods_running_as_root.txt"
echo -e "${BOLD}${UNDERLINE}Identify Pods Running as Root${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get pods --namespace "$namespace" -o json | jq '.items[] | select(.spec.containers[]?.securityContext?.runAsUser == 0) | .metadata.name' | tee -a "$section_file" "$combined_file"
check_error

# Section 21: Inspect Pod Capabilities
section_file="${output_folder}/pod_capabilities.txt"
echo -e "${BOLD}${UNDERLINE}Inspect Pod Capabilities${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get pods --namespace "$namespace" -o json | jq '.items[] | select(.spec.containers[]?.securityContext?.capabilities) | .metadata.name' | tee -a "$section_file" "$combined_file"
check_error

# Section 22: Check Pods in kube-system Namespace
section_file="${output_folder}/kube_system_pods.txt"
echo -e "${BOLD}${UNDERLINE}Check Pods in kube-system Namespace${RESET}" | tee -a "$section_file" "$combined_file"
kubectl get pods -n kube-system | tee -a "$section_file" "$combined_file"
check_error

# Section 23: Review API Server Pods
section_file="${output_folder}/apiserver_pods.txt"
echo -e "${BOLD}${UNDERLINE}Review API Server Pods${RESET}" | tee -a "$section_file" "$combined_file"
kubectl -n kube-system get pods | grep kube-apiserver | awk '{print $1}' | while read pod; do
    kubectl -n kube-system describe pod "$pod" | tee -a "$section_file" "$combined_file"
done
check_error

echo -e "${BOLD}Security review for namespace ${namespace} completed and saved in folder ${output_folder} (combined output: ${combined_file})${RESET}"
