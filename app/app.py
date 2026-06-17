import os
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from kubernetes import client, config

# Import all your utility helper functions
from app.utils import (
    build_api_groups_root,
    build_api_group_details,
    build_api_resource_list,
    build_dns_endpoint_manifest,
    build_allow_response
)

app = FastAPI(title="Cert-Manager ExternalDNS Webhook")

# Initialize Kubernetes Cluster Client Context
try:
    config.load_incluster_config()
except config.ConfigException:
    config.load_kube_config()

custom_api = client.CustomObjectsApi()

# Environment Single Source of truth string injected from your Helm values.yaml

def get_api_group_name() -> str:
    return os.environ.get("API_GROUP_NAME", "://myorg.com")


# Pydantic Structural Contract validation schemas
class AdmissionRequest(BaseModel):
    uid: str
    object: dict

class AdmissionReviewInput(BaseModel):
    apiVersion: str
    kind: str
    request: AdmissionRequest


# ==============================================================================
# PROBES & OPERATIONAL SYSTEM LIFECYCLE ROUTING
# ==============================================================================

@app.get("/healthz", status_code=status.HTTP_200_OK)
def healthz():
    """Liveness and Readiness probe endpoint used by the Kubelet over HTTPS."""
    return {"status": "healthy"}


@app.get("/openapi/v2", status_code=status.HTTP_200_OK)
def openapi_v2_discovery():
    """Satisfies the Kubernetes API Server background documentation sweeps."""
    return {
        "swagger": "2.0",
        "info": {"title": "Cert-Manager ExternalDNS Webhook", "version": "v1alpha1"},
        "paths": {}
    }


# ==============================================================================
# KUBERNETES CONTROL PLANE API AGGREGATION DISCOVERY ENDPOINTS
# ==============================================================================

@app.get("/apis", status_code=status.HTTP_200_OK)
def api_groups_root():
    """Root discovery endpoint telling Kubernetes what API groups this server hosts."""
    api_group = get_api_group_name()
    return build_api_groups_root(api_group)


@app.get("/apis/{group}", status_code=status.HTTP_200_OK)
def api_group_details(group: str):
    """Dynamic metadata lookup for the API group."""
    api_group = get_api_group_name()
    if group != api_group:
        raise HTTPException(status_code=404, detail="API Group layout mismatch.")
    return build_api_group_details(api_group)


@app.get("/apis/{group}/{version}", status_code=status.HTTP_200_OK)
def api_group_version_resources(group: str, version: str):
    """Confirms that this group version handles 'challengerequests'."""
    api_group = get_api_group_name()
    if group != api_group or version != "v1alpha1":
        raise HTTPException(status_code=404, detail="API Version or Group mismatch.")
    return build_api_resource_list(api_group)


@app.get("/apis/{group}/{version}/namespaces/{namespace}/challengerequests", status_code=status.HTTP_200_OK)
def api_group_list_watch_handler(group: str, version: str, namespace: str):
    """Satisfies the cluster's automatic back-end watch and list syncing checks."""
    api_group = get_api_group_name()
    if group != api_group or version != "v1alpha1":
        raise HTTPException(status_code=404)
    return {
        "kind": "ChallengeRequestList",
        "apiVersion": f"{api_group}/v1alpha1",
        "metadata": {"selfLink": f"/apis/{group}/{version}/namespaces/{namespace}/challengerequests"},
        "items": [] # Returns empty slice list to confirm schema readiness
    }


# ==============================================================================
# MUTATION AND STATE LIFECYCLE LOGIC (The core webhook functions)
# ==============================================================================

@app.post("/apis/{group}/{version}/namespaces/{namespace}/challengerequests/{solver}", status_code=status.HTTP_200_OK)
def webhook_control_router(group: str, version: str, namespace: str, solver: str, review: AdmissionReviewInput):
    """
    Main cluster endpoint hit by cert-manager challenges.
    Differentiates traffic based on 'spec.action' parameter flags.
    """
    api_group = get_api_group_name()
    if group != api_group or version != "v1alpha1":
        raise HTTPException(status_code=404, detail="API group or version path mismatch.")

    req = review.request
    challenge = req.object

    try:
        action_type = challenge['spec']['action']
    except KeyError:
        raise HTTPException(status_code=400, detail="Missing spec.action payload parameters.")

    # Divert workflows to separate decoupled business actions
    if action_type == "PRESENT":
        return process_present_action(req.uid, namespace, challenge)
    elif action_type == "CLEANUP":
        return process_cleanup_action(req.uid, namespace, challenge)
    else:
        return build_allow_response(req.uid, success=False, message=f"Unknown action: {action_type}")


def process_present_action(admission_uid: str, namespace: str, challenge: dict) -> dict:
    """ENDPOINT 1: Creation lifecycle logic for generating the DNSEndpoint CRD."""
    try:
        token = challenge['spec']['key']
        uid = challenge['metadata']['uid']
        challenge_name = challenge['metadata']['name']
        raw_fqdn = challenge['spec']['dnsName']
    except KeyError as e:
        return build_allow_response(admission_uid, success=False, message=f"Missing spec metadata key: {e}")

    dns_endpoint = build_dns_endpoint_manifest(
        uid=uid, namespace=namespace, challenge_name=challenge_name, 
        resolved_fqdn=raw_fqdn, token=token
    )

    try:
        custom_api.create_namespaced_custom_object(
            group="externaldns.k8s.io", version="v1alpha1",
            namespace=namespace, plural="dnsendpoints", body=dns_endpoint
        )
        return build_allow_response(admission_uid, success=True)
    except Exception as e:
        return build_allow_response(admission_uid, success=False, message=f"K8s Manifest Creation Failed: {str(e)}")


def process_cleanup_action(admission_uid: str, namespace: str, challenge: dict) -> dict:
    """ENDPOINT 2: Deletion lifecycle logic for pruning the DNSEndpoint CRD."""
    try:
        uid = challenge['metadata']['uid']
    except KeyError as e:
        return build_allow_response(admission_uid, success=False, message=f"Missing unique reference: {e}")

    try:
        custom_api.delete_namespaced_custom_object(
            group="externaldns.k8s.io", version="v1alpha1",
            namespace=namespace, plural="dnsendpoints", name=f"cm-challenge-{uid}"
        )
    except client.exceptions.ApiException as e:
        if e.status != 404: # Safely bypass if already cleaned via OwnerReferences
            return build_allow_response(admission_uid, success=False, message=f"K8s Resource Prune Failed: {str(e)}")
            
    return build_allow_response(admission_uid, success=True)


if __name__ == "__main__":
    import uvicorn
    # Boots secure server over HTTPS using files mounted to /tls by Helm
    uvicorn.run(
        "app:app", host="0.0.0.0", port=10250,
        ssl_keyfile="/tls/tls.key", ssl_certfile="/tls/tls.crt"
    )
