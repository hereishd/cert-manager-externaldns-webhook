# Custom cert-manager Webhook for Azure Private DNS via External-DNS

This repository contains a custom **cert-manager Webhook Server** written in Python using **FastAPI**. It bridges the gap between public/private ACME certificate management workflows and internal **Azure Private DNS Zones** by dynamically converting challenge events into cluster native **`DNSEndpoint`** resources.

# 1. Architectural Overview

When requesting a TLS certificate for a private corporate network, public Certificate Authorities (like Let's Encrypt) or internal ACME servers must prove domain ownership via a `DNS-01` challenge. Because maintaining dozens of native cloud provider tools natively within the core cert-manager repository is unfeasible, cert-manager uses an out-of-tree extension webhook pattern [cert-manager.io].

This webhook implements a zero-cloud-dependency, event-driven translation engine:

1. **Challenge Issuance**: `cert-manager` receives a certificate request and compiles a `Challenge` lifecycle resource [cert-manager.io].
2. **Webhook Translation**: The `APIService` routes the lifecycle payload directly to this custom Python Webhook server over HTTPS [cert-manager.io].
3. **Resource Injection**: The Python server strips trailing FQDN dots, formats the security strings, and creates a local `DNSEndpoint` Custom Resource (CRD) inside the cluster database.
4. **Cloud Synchronization**: The `external-dns` controller (which already has native IAM permissions to modify your corporate Azure Private DNS Zones) detects the new `DNSEndpoint` object and writes the target `TXT` record into Azure.
5. **Pruning and Teardown**: Once verified, cert-manager issues a cleanup command. The webhook prunes the `DNSEndpoint` CRD, and `external-dns` purges the temporary tracking record from Azure, preventing resource leakage.

## 2. Understanding the Kubernetes `APIService` Object

A standard webhook uses basic Admission Webhooks (mutating/validating). However, cert-manager leverages the **Kubernetes API Aggregation Layer** via an **`APIService`** resource [cert-manager.io]. 

### What is an APIService?
An `APIService` tells the core Kubernetes Control Plane (the master API server) that your application pod is **not a standard backend website**, but rather an **Extension API Server** that stretches the native capabilities of Kubernetes itself [cert-manager.io]. It registers a dedicated, custom path URL group (e.g., `://myorg.com`) directly inside the core cluster architecture [cert-manager.io].

### Why Must our App Host Discovery Endpoints?
Because your Python script acts as an API Extension Server, the Kubernetes master nodes must perform continuous **Discovery Sweeps** and **Sync Loops** against it [cert-manager.io]. 
* Kubernetes constantly checks your app to ask: *"What version do you speak?"*, *"What objects do you control?"*, and *"What is your OpenAPI documentation schema?"*
* If your application fails to handle these discovery sweeps or throws a `404 Not Found` error, the master node flags the `APIService` as degraded or failing (`faileddiscoverycheck failing`), blocking cert-manager from ever initiating a challenge.
