import os
import pytest
from fastapi.testclient import TestClient
from kubernetes.client.exceptions import ApiException

# Import the FastAPI application instance and utility helper schemas
from app import app
from app.utils import (
    clean_fqdn,
    build_dns_endpoint_manifest,
    build_allow_response,
    build_api_groups_root,
    build_api_group_details,
    build_api_resource_list
)

# Initialize the lightweight FastAPI mock server testing engine
client = TestClient(app)

# Standard mock cert-manager ChallengeRequest payload
def get_mock_payload(action: str) -> dict:
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "test-admission-uid-999",
            "object": {
                "metadata": {
                    "uid": "challenge-uid-123",
                    "namespace": "cert-manager",
                    "name": "example-cert-challenge"
                },
                "spec": {
                    "action": action, # Dynamic parameter: PRESENT or CLEANUP
                    "dnsName": "_://example.com.",
                    "key": "mock-acme-token-xyz"
                }
            }
        }
    }

# ==============================================================================
# 1. UTILS.PY SCHEMA & FORMATTING UNIT TESTS
# ==============================================================================

def test_clean_fqdn_utility():
    """Assert clean_fqdn safely strips trailing dots or leaves clean domains alone."""
    assert clean_fqdn("example.com.") == "example.com"
    assert clean_fqdn("://domain.com") == "://domain.com"


def test_build_dns_endpoint_manifest_structure():
    """Assert manifest creation maps properties into correct external-dns dictionary formats."""
    manifest = build_dns_endpoint_manifest(
        uid="123",
        namespace="dev",
        challenge_name="test-cert",
        resolved_fqdn="_://example.com.",
        token="token123"
    )
    
    endpoint = manifest["spec"]["endpoints"][0]
    assert endpoint["dnsName"] == "_://example.com"
    assert endpoint["targets"] == ['"token123"'] # Embedded internal double quotes
    
    owner = manifest["metadata"]["ownerReferences"][0]
    assert owner["kind"] == "Challenge"
    assert owner["name"] == "test-cert"


def test_build_allow_response_formatting():
    """Assert admission review responses output expected status schemas."""
    success_resp = build_allow_response(uid="abc", success=True)
    assert success_resp["response"]["allowed"] is True
    assert success_resp["response"]["status"]["message"] == ""


# ==============================================================================
# 2. REFACTORED API AGGREGATION DISCOVERY ENDPOINTS TESTS
# ==============================================================================

def test_healthz_endpoint():
    """Assert the health probe returns HTTP 200 for liveness/readiness checks."""
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_openapi_v2_endpoint():
    """Assert /openapi/v2 returns a valid base Swagger 2.0 shell mapping."""
    response = client.get("/openapi/v2")
    assert response.status_code == 200
    assert response.json()["swagger"] == "2.0"


def test_api_groups_root_endpoint(monkeypatch):
    """Assert /apis lists the exact group name declared in your environment variable."""
    test_group = "dnswebhook.myorg.com"
    monkeypatch.setenv("API_GROUP_NAME", test_group)
    
    response = client.get("/apis")
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["kind"] == "APIGroupList"
    assert json_data["groups"][0]["name"] == test_group


def test_api_group_details_endpoint_success(monkeypatch):
    """Assert /apis/{group} routes correctly when matching the valid active groupName."""
    test_group = "dnswebhook.myorg.com"
    monkeypatch.setenv("API_GROUP_NAME", test_group)
    
    response = client.get(f"/apis/{test_group}")
    assert response.status_code == 200
    assert response.json()["name"] == test_group


def test_api_group_details_endpoint_404(monkeypatch):
    """Assert /apis/{group} explicitly throws an HTTP 404 security rejection for unmatched groups."""
    monkeypatch.setenv("API_GROUP_NAME", "my-real-secure-group.com")
    
    response = client.get("/apis/unauthorized-random-group-request")
    assert response.status_code == 404


def test_api_group_version_resources_success(monkeypatch):
    """Assert version resource path announces ChallengeRequests capability over 'create', 'list', 'watch'."""
    test_group = "dnswebhook.myorg.com"
    monkeypatch.setenv("API_GROUP_NAME", test_group)
    
    response = client.get(f"/apis/{test_group}/v1alpha1")
    assert response.status_code == 200
    
    resource = response.json()["resources"][0]
    assert resource["name"] == "challengerequests"
    assert "create" in resource["verbs"]
    assert "list" in resource["verbs"]


def test_api_group_list_watch_handler_endpoint(monkeypatch):
    """Assert the GET namespace resource syncing handler returns an empty tracking slice list."""
    test_group = "dnswebhook.myorg.com"
    monkeypatch.setenv("API_GROUP_NAME", test_group)
    
    target_url = f"/apis/{test_group}/v1alpha1/namespaces/cert-manager/challengerequests"
    response = client.get(target_url)
    
    assert response.status_code == 200
    assert response.json()["kind"] == "ChallengeRequestList"
    assert response.json()["items"] == [] # Crucial empty array for K8s synchronization


# ==============================================================================
# 3. MUTATION WORKFLOW & STATE LIFECYCLE LOGIC POST TESTS
# ==============================================================================

def test_webhook_router_present_action_success(mocker, monkeypatch):
    """Assert a POST with action=PRESENT dynamically routes and creates the DNSEndpoint resource."""
    test_group = "dnswebhook.myorg.com"
    monkeypatch.setenv("API_GROUP_NAME", test_group)
    
    mock_create = mocker.patch("app.custom_api.create_namespaced_custom_object")
    mock_create.return_value = {}

    target_url = f"/apis/{test_group}/v1alpha1/namespaces/cert-manager/challengerequests/solver-profile"
    response = client.post(target_url, json=get_mock_payload("PRESENT"))
    
    assert response.status_code == 200
    assert response.json()["response"]["allowed"] is True
    mock_create.assert_called_once()


def test_webhook_router_cleanup_action_success(mocker, monkeypatch):
    """Assert a POST with action=CLEANUP dynamically routes and deletes the DNSEndpoint resource."""
    test_group = "dnswebhook.myorg.com"
    monkeypatch.setenv("API_GROUP_NAME", test_group)
    
    mock_delete = mocker.patch("app.custom_api.delete_namespaced_custom_object")
    mock_delete.return_value = {}

    target_url = f"/apis/{test_group}/v1alpha1/namespaces/cert-manager/challengerequests/solver-profile"
    response = client.post(target_url, json=get_mock_payload("CLEANUP"))
    
    assert response.status_code == 200
    assert response.json()["response"]["allowed"] is True
    mock_delete.assert_called_once_with(
        group="externaldns.k8s.io",
        version="v1alpha1",
        namespace="cert-manager",
        plural="dnsendpoints",
        name="cm-challenge-challenge-uid-123"
    )


def test_webhook_router_handles_malformed_action_type(monkeypatch):
    """Assert the POST router rejects payloads containing unassigned execution actions."""
    test_group = "dnswebhook.myorg.com"
    monkeypatch.setenv("API_GROUP_NAME", test_group)
    
    target_url = f"/apis/{test_group}/v1alpha1/namespaces/cert-manager/challengerequests/solver-profile"
    response = client.post(target_url, json=get_mock_payload("INVALID_ACTION_NAME"))
    
    assert response.status_code == 200
    assert response.json()["response"]["allowed"] is False
    assert "Unknown action" in response.json()["response"]["status"]["message"]
