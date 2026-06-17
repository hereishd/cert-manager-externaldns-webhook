def clean_fqdn(dns_name: str) -> str:
    """Strips the trailing dot from cert-manager's FQDN if it exists."""
    return dns_name.rstrip('.')


def build_dns_endpoint_manifest(uid: str, namespace: str, challenge_name: str, resolved_fqdn: str, token: str) -> dict:
    """Generates the structured DNSEndpoint Custom Resource payload for external-dns."""
    return {
        "apiVersion": "externaldns.k8s.io/v1alpha1",
        "kind": "DNSEndpoint",
        "metadata": {
            "name": f"cm-challenge-{uid}",
            "namespace": namespace,
            "ownerReferences": [{
                "apiVersion": "cert-manager.io/v1",
                "kind": "Challenge",
                "name": challenge_name,
                "uid": uid
            }]
        },
        "spec": {
            "endpoints": [{
                "dnsName": clean_fqdn(resolved_fqdn),
                "recordType": "TXT",
                "ttl": 60,
                "targets": [f'"{token}"']
            }]
        }
    }


def build_allow_response(uid: str, success: bool, message: str = "") -> dict:
    """Formats the JSON response back to cert-manager's AdmissionReview controller."""
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": success,
            "status": {"message": message}
        }
    }


def build_api_groups_root(group_name: str) -> dict:
    """Generates the top-level APIGroupList payload for /apis."""
    return {
        "kind": "APIGroupList",
        "apiVersion": "v1",
        "groups": [
            {
                "name": group_name,
                "versions": [{"groupVersion": f"{group_name}/v1alpha1", "version": "v1alpha1"}],
                "preferredVersion": {"groupVersion": f"{group_name}/v1alpha1", "version": "v1alpha1"}
            }
        ]
    }


def build_api_group_details(group_name: str) -> dict:
    """Generates the detailed APIGroup payload for /apis/{group}."""
    return {
        "kind": "APIGroup",
        "apiVersion": "v1",
        "name": group_name,
        "versions": [{"groupVersion": f"{group_name}/v1alpha1", "version": "v1alpha1"}],
        "preferredVersion": {"groupVersion": f"{group_name}/v1alpha1", "version": "v1alpha1"}
    }


def build_api_resource_list(group_name: str) -> dict:
    """Generates the APIResourceList confirming this server handles ChallengeRequests."""
    return {
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": f"{group_name}/v1alpha1",
        "resources": [
            {
                "name": "challengerequests",
                "singularName": "challengerequest",
                "namespaced": True,
                "kind": "ChallengeRequest",
                "verbs": ["create", "list", "watch"]
            }
        ]
    }