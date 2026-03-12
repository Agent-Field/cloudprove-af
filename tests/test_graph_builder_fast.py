from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from cloudsecurity_af.agents.recon._graph_builder_fast import (
    _cluster_key,
    _infer_edge_type,
    build_graph_from_inventory,
)


class TestInferEdgeType:
    def test_iam_role_is_trust(self) -> None:
        assert _infer_edge_type("aws_iam_role", "aws_s3_bucket") == "trust"

    def test_k8s_serviceaccount_is_trust(self) -> None:
        assert _infer_edge_type("serviceaccount", "clusterrolebinding") == "trust"

    def test_k8s_clusterrole_is_trust(self) -> None:
        assert _infer_edge_type("clusterrole", "pod") == "trust"

    def test_vpc_is_network(self) -> None:
        assert _infer_edge_type("aws_vpc", "aws_subnet") == "network_path"

    def test_k8s_ingress_is_network(self) -> None:
        assert _infer_edge_type("ingress", "service") == "network_path"

    def test_k8s_networkpolicy_is_network(self) -> None:
        assert _infer_edge_type("networkpolicy", "pod") == "network_path"

    def test_k8s_service_is_network(self) -> None:
        assert _infer_edge_type("service", "deployment") == "network_path"

    def test_s3_bucket_is_data_access(self) -> None:
        assert _infer_edge_type("aws_s3_bucket", "aws_lambda_function") == "data_access"

    def test_k8s_configmap_is_data_access(self) -> None:
        assert _infer_edge_type("configmap", "deployment") == "data_access"

    def test_k8s_secret_is_data_access(self) -> None:
        assert _infer_edge_type("secret", "pod") == "data_access"

    def test_k8s_persistentvolume_is_data_access(self) -> None:
        assert _infer_edge_type("persistentvolume", "pod") == "data_access"

    def test_lambda_to_role_is_trust(self) -> None:
        assert _infer_edge_type("aws_lambda_function", "aws_iam_role") == "trust"

    def test_lambda_to_unknown_is_execution(self) -> None:
        assert _infer_edge_type("aws_lambda_function", "aws_cloudwatch_log_group") == "execution"

    def test_deployment_to_configmap_is_data_access(self) -> None:
        assert _infer_edge_type("deployment", "configmap") == "data_access"

    def test_deployment_to_unknown_is_execution(self) -> None:
        assert _infer_edge_type("deployment", "namespace") == "execution"

    def test_statefulset_to_pvc_is_data_access(self) -> None:
        assert _infer_edge_type("statefulset", "persistentvolumeclaim") == "data_access"

    def test_cronjob_to_unknown_is_execution(self) -> None:
        assert _infer_edge_type("cronjob", "namespace") == "execution"

    def test_unknown_defaults_to_references(self) -> None:
        assert _infer_edge_type("unknown_thing", "another_thing") == "references"


class TestClusterKey:
    def test_aws_vpc_clusters_to_network(self) -> None:
        r = {"type": "aws_vpc", "provider": "aws", "file_path": "modules/net/main.tf"}
        assert _cluster_key(r).startswith("network/")

    def test_k8s_deployment_clusters_to_compute(self) -> None:
        r = {"type": "Deployment", "provider": "kubernetes", "file_path": "k8s/app.yaml"}
        assert _cluster_key(r).startswith("compute/")

    def test_k8s_networkpolicy_clusters_to_network(self) -> None:
        r = {"type": "NetworkPolicy", "provider": "kubernetes", "file_path": "k8s/policy.yaml"}
        assert _cluster_key(r).startswith("network/")

    def test_k8s_clusterrole_clusters_to_identity(self) -> None:
        r = {"type": "ClusterRole", "provider": "kubernetes", "file_path": "k8s/rbac.yaml"}
        assert _cluster_key(r).startswith("identity/")

    def test_k8s_configmap_clusters_to_data(self) -> None:
        r = {"type": "ConfigMap", "provider": "kubernetes", "file_path": "k8s/config.yaml"}
        assert _cluster_key(r).startswith("data/")

    def test_k8s_unknown_type_falls_to_k8s_cluster(self) -> None:
        r = {"type": "CustomResource", "provider": "kubernetes", "file_path": "k8s/custom.yaml"}
        assert _cluster_key(r).startswith("k8s/")

    def test_docker_unknown_type_falls_to_docker_cluster(self) -> None:
        r = {"type": "docker_service", "provider": "docker", "file_path": "compose.yaml"}
        assert _cluster_key(r).startswith("docker/")

    def test_generic_falls_to_general(self) -> None:
        r = {"type": "something_else", "provider": "other", "file_path": "main.tf"}
        assert _cluster_key(r).startswith("general/")


class TestBuildGraphFromInventory:
    def _write_inventory(self, tmp_dir: str, resources: list) -> str:
        inv_path = os.path.join(tmp_dir, "inventory.json")
        with open(inv_path, "w") as f:
            json.dump({"resources": resources}, f)
        return inv_path

    def test_k8s_resources_produce_valid_graph(self, tmp_path: Path) -> None:
        resources = [
            {
                "id": "Deployment/nginx",
                "type": "Deployment",
                "name": "nginx",
                "provider": "kubernetes",
                "file_path": "k8s/deploy.yaml",
                "config": {"securitycontext": {"runAsNonRoot": True}},
                "references": ["Service/nginx"],
                "referenced_by": [],
            },
            {
                "id": "Service/nginx",
                "type": "Service",
                "name": "nginx",
                "provider": "kubernetes",
                "file_path": "k8s/svc.yaml",
                "config": {"port": 80},
                "references": [],
                "referenced_by": ["Deployment/nginx"],
            },
        ]
        inv_path = self._write_inventory(str(tmp_path), resources)
        out_dir = str(tmp_path / "out")
        graph_path, total_nodes, total_edges = build_graph_from_inventory(inv_path, out_dir)

        assert total_nodes == 2
        assert total_edges >= 1
        assert Path(graph_path).exists()

        with open(graph_path) as f:
            graph = json.load(f)
        assert len(graph["nodes"]) == 2
        edge_types = {e["type"] for e in graph["edges"]}
        assert edge_types & {"network_path", "execution"}

    def test_mixed_format_inventory(self, tmp_path: Path) -> None:
        resources = [
            {
                "id": "aws_s3_bucket.data",
                "type": "aws_s3_bucket",
                "name": "data",
                "provider": "aws",
                "file_path": "main.tf",
                "config": {"acl": "private", "encryption": True},
                "references": [],
                "referenced_by": [],
            },
            {
                "id": "Deployment/api",
                "type": "Deployment",
                "name": "api",
                "provider": "kubernetes",
                "file_path": "k8s/api.yaml",
                "config": {"privileged": False},
                "references": [],
                "referenced_by": [],
            },
        ]
        inv_path = self._write_inventory(str(tmp_path), resources)
        out_dir = str(tmp_path / "out")
        graph_path, total_nodes, total_edges = build_graph_from_inventory(inv_path, out_dir)

        assert total_nodes == 2
        with open(graph_path) as f:
            graph = json.load(f)
        cluster_names = [c["name"] for c in graph["clusters"]]
        has_data = any("data/" in n for n in cluster_names)
        has_compute = any("compute/" in n for n in cluster_names)
        assert has_data
        assert has_compute

    def test_security_attrs_include_k8s_fields(self, tmp_path: Path) -> None:
        resources = [
            {
                "id": "Deployment/priv",
                "type": "Deployment",
                "name": "priv",
                "provider": "kubernetes",
                "file_path": "k8s/priv.yaml",
                "config": {
                    "privileged": True,
                    "hostnetwork": True,
                    "securitycontext": "runAsRoot",
                    "image": "nginx:latest",
                },
                "references": [],
                "referenced_by": [],
            },
        ]
        inv_path = self._write_inventory(str(tmp_path), resources)
        out_dir = str(tmp_path / "out")
        graph_path, _, _ = build_graph_from_inventory(inv_path, out_dir)

        with open(graph_path) as f:
            graph = json.load(f)
        node = graph["nodes"][0]
        assert "privileged" in node["config_summary"]
        assert "hostnetwork" in node["config_summary"]
        assert "securitycontext" in node["config_summary"]
        assert "image" not in node["config_summary"]

    def test_empty_inventory(self, tmp_path: Path) -> None:
        inv_path = self._write_inventory(str(tmp_path), [])
        out_dir = str(tmp_path / "out")
        graph_path, total_nodes, total_edges = build_graph_from_inventory(inv_path, out_dir)
        assert total_nodes == 0
        assert total_edges == 0
