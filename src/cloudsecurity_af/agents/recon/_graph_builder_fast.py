from __future__ import annotations

import json
import os
from typing import Any

_EDGE_TYPE_MAP = {
    # --- Specific multi-word keys first (must match before their substrings) ---
    "networkpolicy": "network_path",
    "serviceaccount": "trust",
    "clusterrolebinding": "trust",
    "clusterrole": "trust",
    "rolebinding": "trust",
    # --- Network ---
    "security_group": "network_path",
    "subnet": "network_path",
    "route": "network_path",
    "vpc": "network_path",
    "lb": "network_path",
    "elb": "network_path",
    "alb": "network_path",
    "nlb": "network_path",
    "gateway": "network_path",
    "igw": "network_path",
    "nat": "network_path",
    "nacl": "network_path",
    "network_interface": "network_path",
    "peering": "network_path",
    "endpoint": "network_path",
    "flow_log": "network_path",
    "ingress": "network_path",
    "service": "network_path",
    "loadbalancer": "network_path",
    # --- IAM / trust ---
    "iam": "trust",
    "role": "trust",
    "policy": "trust",
    "assume": "trust",
    "managedidentity": "trust",
    # --- Data access (AWS, GCP, Azure, K8s) ---
    "bucket": "data_access",
    "dynamodb": "data_access",
    "rds": "data_access",
    "db_instance": "data_access",
    "db_subnet": "data_access",
    "db_option": "data_access",
    "db_parameter": "data_access",
    "s3": "data_access",
    "kms": "data_access",
    "sqs": "data_access",
    "sns": "data_access",
    "neptune": "data_access",
    "elasticsearch": "data_access",
    "es_domain": "data_access",
    "redshift": "data_access",
    "ebs": "data_access",
    "efs": "data_access",
    "backup": "data_access",
    "snapshot": "data_access",
    "configmap": "data_access",
    "secret": "data_access",
    "persistentvolume": "data_access",
    "persistentvolumeclaim": "data_access",
    "storageclass": "data_access",
    "volume": "data_access",
    # --- Execution (AWS, GCP, Azure, K8s, Docker) ---
    "lambda": "execution",
    "function": "execution",
    "instance": "execution",
    "ecs": "execution",
    "eks": "execution",
    "ecr": "execution",
    "task": "execution",
    "fargate": "execution",
    "node_group": "execution",
    "launch_template": "execution",
    "auto_scaling": "execution",
    "deployment": "execution",
    "statefulset": "execution",
    "daemonset": "execution",
    "replicaset": "execution",
    "cronjob": "execution",
    "job": "execution",
    "pod": "execution",
    "container": "execution",
}


def _infer_edge_type(source_type: str, target_type: str) -> str:
    src = source_type.lower()
    tgt = target_type.lower()
    for keyword, etype in _EDGE_TYPE_MAP.items():
        if keyword in src or keyword in tgt:
            return etype
    return "references"


def _cluster_key(resource: dict[str, Any]) -> str:
    rtype = resource.get("type", "").lower()
    provider = resource.get("provider", "").lower()
    file_path = resource.get("file_path", "")
    parts = file_path.split("/")
    module_dir = "/".join(parts[:-1]) if len(parts) > 1 else "root"

    _NETWORK_KW = (
        "vpc",
        "subnet",
        "security_group",
        "route",
        "gateway",
        "igw",
        "nat",
        "nacl",
        "elb",
        "alb",
        "nlb",
        "lb",
        "network_interface",
        "peering",
        "endpoint",
        "flow_log",
        "ingress",
        "networkpolicy",
        "loadbalancer",
    )
    _IDENTITY_KW = (
        "iam",
        "role",
        "policy",
        "user",
        "group",
        "access_key",
        "clusterrole",
        "clusterrolebinding",
        "rolebinding",
        "serviceaccount",
        "managedidentity",
    )
    _DATA_KW = (
        "s3",
        "bucket",
        "rds",
        "db_instance",
        "dynamodb",
        "neptune",
        "elasticsearch",
        "redshift",
        "ebs",
        "efs",
        "kms",
        "snapshot",
        "backup",
        "configmap",
        "secret",
        "persistentvolume",
        "persistentvolumeclaim",
        "storageclass",
        "volume",
    )
    _COMPUTE_KW = (
        "lambda",
        "function",
        "instance",
        "ecs",
        "eks",
        "ecr",
        "fargate",
        "deployment",
        "statefulset",
        "daemonset",
        "replicaset",
        "cronjob",
        "job",
        "pod",
        "container",
    )

    if any(kw in rtype for kw in _NETWORK_KW):
        return f"network/{module_dir}"
    if any(kw in rtype for kw in _IDENTITY_KW):
        return f"identity/{module_dir}"
    if any(kw in rtype for kw in _DATA_KW):
        return f"data/{module_dir}"
    if any(kw in rtype for kw in _COMPUTE_KW):
        return f"compute/{module_dir}"

    if provider == "kubernetes":
        return f"k8s/{module_dir}"
    if provider == "docker":
        return f"docker/{module_dir}"

    return f"general/{module_dir}"


def build_graph_from_inventory(inventory_path: str, output_dir: str) -> tuple[str, int, int]:
    """Build a ResourceGraph JSON from inventory.json deterministically.

    Returns (graph_json_path, total_nodes, total_edges).
    """
    with open(inventory_path, "r") as f:
        inv = json.load(f)

    if not isinstance(inv, dict):
        inv = {"resources": []}
    raw_resources = inv.get("resources", [])
    if not isinstance(raw_resources, list):
        raw_resources = []

    resources = [r for r in raw_resources if isinstance(r, dict)]

    nodes: list[dict[str, Any]] = []
    resource_ids: set[str] = set()
    for r in resources:
        rid = r.get("id", "")
        resource_ids.add(rid)
        config = r.get("config", {})
        security_attrs = {
            k: v
            for k, v in (config if isinstance(config, dict) else {}).items()
            if any(
                kw in k.lower()
                for kw in (
                    "encrypt",
                    "public",
                    "acl",
                    "policy",
                    "logging",
                    "ssl",
                    "tls",
                    "secret",
                    "password",
                    "key",
                    "auth",
                    "cidr",
                    "ingress",
                    "egress",
                    "port",
                    "protocol",
                    "versioning",
                    "privileged",
                    "capability",
                    "securitycontext",
                    "runasuser",
                    "runasroot",
                    "readonly",
                    "hostnetwork",
                    "hostpid",
                    "hostipc",
                    "serviceaccount",
                    "networkmode",
                    "expose",
                    "environment",
                )
            )
        }
        nodes.append(
            {
                "resource_id": rid,
                "resource_type": r.get("type", ""),
                "provider": r.get("provider", ""),
                "file_path": r.get("file_path", ""),
                "config_summary": security_attrs,
            }
        )

    edges: list[dict[str, Any]] = []
    seen_edges: set[str] = set()
    for r in resources:
        source_id = r.get("id", "")
        source_type = r.get("type", "")
        for ref in r.get("references", []):
            if ref in resource_ids and ref != source_id:
                edge_key = f"{source_id}->{ref}"
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    edges.append(
                        {
                            "source": source_id,
                            "target": ref,
                            "type": _infer_edge_type(source_type, ref),
                        }
                    )
        for ref_by in r.get("referenced_by", []):
            if ref_by in resource_ids and ref_by != source_id:
                edge_key = f"{ref_by}->{source_id}"
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    edges.append(
                        {
                            "source": ref_by,
                            "target": source_id,
                            "type": _infer_edge_type(ref_by, source_type),
                        }
                    )

    cluster_map: dict[str, list[str]] = {}
    for r in resources:
        ck = _cluster_key(r)
        cluster_map.setdefault(ck, []).append(r.get("id", ""))
    clusters = [{"name": name, "members": members} for name, members in sorted(cluster_map.items())]

    graph = {"nodes": nodes, "edges": edges, "clusters": clusters}

    os.makedirs(output_dir, exist_ok=True)
    graph_path = os.path.join(output_dir, "graph.json")
    with open(graph_path, "w") as f:
        json.dump(graph, f, indent=2, default=str)

    return graph_path, len(nodes), len(edges)
