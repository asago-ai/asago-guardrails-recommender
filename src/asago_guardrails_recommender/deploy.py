"""
NemoGuardrails manifest generator.

Generates:
- CR mode (default): multi-doc YAML with ConfigMaps and a NemoGuardrails CR
- Standalone mode: Deployment + Service + ConfigMaps for direct pod execution

Does NOT apply anything to the cluster (manifest-only).

Usage:
  python3 -m recommender.deploy --run-dir /path/to/run [--namespace llm-serving]
    [--name asago-rec] [--configs name1 name2 ...] [--out <path>] [--cpu 4] [--memory 16Gi]
  python3 -m recommender.deploy --run-dir /path/to/run --mode standalone [--image IMAGE]
    [--namespace llm-serving] [--name asago-nemo36] [--configs name1 name2 ...] [--out <path>]
"""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path
from typing import Any

import yaml

# VALIDATION

CONFIG_ID_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
DEFAULT_IMAGE = (
    "quay.io/trustyai/nemo-guardrails-server@sha256:bf08994e25d84f03b5182f5505cb8358e99e2d5a8879a64728322fd569b6c327"
)
MAX_VOLUME_NAME_LEN = 63


def validate_config_id(config_id: str) -> bool:
    """Check if config_id matches RFC 1123 (lowercase alphanumerics and '-', start/end alphanumeric)."""
    return bool(CONFIG_ID_PATTERN.match(config_id))


def dns_safe_name(folder_name: str, max_len: int = 63) -> str:
    """
    Convert folder name to DNS-1123 safe name.
    Replace '_' with '-', replace invalid chars with '-'.
    If longer than max_len, truncate and append a short hash.
    """
    # Replace underscore with dash
    safe = folder_name.lower().replace("_", "-")

    # Replace invalid chars with dash
    safe = re.sub(r"[^a-z0-9-]", "-", safe)

    # Remove leading/trailing dashes
    safe = safe.strip("-")

    # If too long, truncate and add hash
    if len(safe) > max_len:
        # Reserve 8 chars for "-XXXXXXXX" hash
        truncate_len = max_len - 9
        base = safe[:truncate_len]
        hash_suffix = hashlib.md5(safe.encode()).hexdigest()[:8]
        safe = f"{base}-{hash_suffix}"

    return safe


# CONFIGMAP BUILDER


def build_configmaps(
    server_configs_dir: Path,
    config_names: list[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """
    Build ConfigMaps from server_configs folders.

    ConfigMap names are generated as: "ar-" + first 8 hex of sha1(config_name)
    Volume name = config_name + "-" + cm_name_suffix + "-volume", validated <= 63 chars.

    Args:
        server_configs_dir: path to server_configs/
        config_names: list of folder names to include (None = all)

    Returns:
        (configmaps, config_id_to_cm_name) tuple
    """
    configmaps = []
    config_id_to_cm_name: dict[str, str] = {}

    if not server_configs_dir.exists():
        return configmaps, config_id_to_cm_name

    # List folders
    for item in sorted(server_configs_dir.iterdir()):
        if not item.is_dir():
            continue

        config_id = item.name

        # Filter by config_names if provided
        if config_names and config_id not in config_names:
            continue

        # Validate folder name (RFC 1123 lowercase)
        if not validate_config_id(config_id):
            raise ValueError(f"Invalid config folder name (must match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$): {config_id}")

        # Read all files in the folder
        cm_data = {}
        for file_path in sorted(item.iterdir()):
            if file_path.is_file():
                key = file_path.name
                with open(file_path) as f:
                    cm_data[key] = f.read()

        if not cm_data:
            continue

        # Generate ConfigMap name: "ar-" + first 8 hex of sha1(config_id)
        config_hash = hashlib.sha1(config_id.encode()).hexdigest()[:8]
        cm_name = f"ar-{config_hash}"
        config_id_to_cm_name[config_id] = cm_name

        # Validate volume name: config_id + "-" + cm_name + "-volume" <= 63 chars
        volume_name = f"{config_id}-{cm_name}-volume"
        if len(volume_name) > MAX_VOLUME_NAME_LEN:
            raise ValueError(
                f"Volume name too long for config '{config_id}': "
                f"'{volume_name}' ({len(volume_name)} > {MAX_VOLUME_NAME_LEN})"
            )

        # Build ConfigMap
        cm = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": cm_name,
                "namespace": "{{ namespace }}",  # Will be replaced
                "labels": {
                    "app.kubernetes.io/part-of": "asago-recommender",
                    "asago.trustyai.io/config-name": config_id,
                },
            },
            "data": cm_data,
        }
        configmaps.append(cm)

    unknown = set(config_names or []) - set(config_id_to_cm_name)
    if unknown:
        raise ValueError(f"Unknown config names (not in server_configs/): {sorted(unknown)}")

    return configmaps, config_id_to_cm_name


# NEMOGUARDRAILS CR BUILDER


def build_nemoguardrails_cr(
    cr_name: str,
    config_id_to_cm_name: dict[str, str],
    env_vars: list[dict[str, Any]] | None = None,
    key_secret_name: str = "litellm-master-key",
) -> dict[str, Any]:
    """Build a NemoGuardrails CR."""
    nemo_configs = []
    default_set = False

    for config_id, cm_name in sorted(config_id_to_cm_name.items()):
        is_default = (config_id == "llm-policy-judge") if not default_set else False
        if is_default:
            default_set = True
        elif not default_set:
            is_default = True
            default_set = True

        nemo_configs.append(
            {
                "name": config_id,
                "configMaps": [cm_name],
                "default": is_default,
            }
        )

    if env_vars is None:
        env_vars = []

    has_api_key = any(e.get("name") == "OPENAI_API_KEY" for e in env_vars)
    if not has_api_key:
        env_vars.append(
            {
                "name": "OPENAI_API_KEY",
                "valueFrom": {
                    "secretKeyRef": {
                        "name": key_secret_name,
                        "key": "master-key",
                        "optional": True,
                    }
                },
            }
        )

    # Build CR
    cr = {
        "apiVersion": "trustyai.opendatahub.io/v1alpha1",
        "kind": "NemoGuardrails",
        "metadata": {
            "name": cr_name,
            "namespace": "{{ namespace }}",  # Will be replaced
        },
        "spec": {
            "nemoConfigs": nemo_configs,
            "env": env_vars,
        },
    }

    return cr


# MANIFEST WRITER


def write_manifest(
    configmaps: list[dict[str, Any]],
    cr: dict[str, Any],
    out_path: Path,
    namespace: str,
) -> None:
    """Write multi-doc YAML manifest."""
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w") as f:
        # ConfigMaps
        for cm in configmaps:
            # Replace namespace placeholder
            cm["metadata"]["namespace"] = namespace
            yaml.dump(cm, f, default_flow_style=False)
            f.write("---\n")

        # CR
        cr["metadata"]["namespace"] = namespace
        yaml.dump(cr, f, default_flow_style=False)


# STANDALONE MODE BUILDER


def build_standalone_deployment(
    name: str,
    image: str,
    config_id_to_cm_name: dict[str, str],
    cpu: str = "4",
    memory: str = "16Gi",
    key_secret_name: str = "litellm-master-key",
) -> dict[str, Any]:
    """Build a Deployment for standalone NeMo Guardrails server."""
    # Parse CPU and memory for requests vs limits
    # For now: requests = limits (or defaults if not specified)
    cpu_request = cpu
    cpu_limit = cpu
    memory_request = memory
    memory_limit = memory

    # Build volume mounts for ConfigMaps
    volumes = []
    volume_mounts = []
    for config_id, cm_name in sorted(config_id_to_cm_name.items()):
        vol_name = cm_name
        volumes.append(
            {
                "name": vol_name,
                "configMap": {
                    "name": cm_name,
                },
            }
        )
        volume_mounts.append(
            {
                "name": vol_name,
                "mountPath": f"/app/config/{config_id}",
            }
        )

    # Determine default config
    default_config = (
        "llm-policy-judge" if "llm-policy-judge" in config_id_to_cm_name else list(config_id_to_cm_name.keys())[0]
    )

    # Build Deployment
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": name,
            "namespace": "{{ namespace }}",  # Will be replaced
        },
        "spec": {
            "replicas": 1,
            "selector": {
                "matchLabels": {
                    "app": name,
                }
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app": name,
                        "app.kubernetes.io/part-of": "asago-recommender",
                    }
                },
                "spec": {
                    "containers": [
                        {
                            "name": "nemo",
                            "image": image,
                            "ports": [
                                {
                                    "containerPort": 8000,
                                    "name": "http",
                                }
                            ],
                            "env": [
                                {
                                    "name": "CONFIG_ID",
                                    "value": default_config,
                                },
                                {
                                    "name": "OPENAI_API_KEY",
                                    "valueFrom": {
                                        "secretKeyRef": {
                                            "name": key_secret_name,
                                            "key": "master-key",
                                            "optional": True,
                                        }
                                    },
                                },
                            ],
                            "resources": {
                                "requests": {
                                    "cpu": cpu_request,
                                    "memory": memory_request,
                                },
                                "limits": {
                                    "cpu": cpu_limit,
                                    "memory": memory_limit,
                                },
                            },
                            "readinessProbe": {
                                "httpGet": {
                                    "path": "/v1/health",
                                    "port": 8000,
                                },
                                "initialDelaySeconds": 20,
                                "periodSeconds": 10,
                            },
                            "volumeMounts": volume_mounts,
                        }
                    ],
                    "volumes": volumes,
                },
            },
        },
    }

    return deployment


def build_standalone_service(name: str) -> dict[str, Any]:
    """
    Build a Service for standalone NeMo Guardrails server.

    Args:
        name: service and deployment name

    Returns:
        Service dict
    """
    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": "{{ namespace }}",  # Will be replaced
        },
        "spec": {
            "type": "ClusterIP",
            "ports": [
                {
                    "port": 80,
                    "targetPort": 8000,
                    "name": "http",
                }
            ],
            "selector": {
                "app": name,
            },
        },
    }

    return service


def write_standalone_manifest(
    configmaps: list[dict[str, Any]],
    deployment: dict[str, Any],
    service: dict[str, Any],
    out_path: Path,
    namespace: str,
) -> None:
    """Write multi-doc YAML manifest for standalone mode."""
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w") as f:
        # ConfigMaps
        for cm in configmaps:
            # Replace namespace placeholder
            cm["metadata"]["namespace"] = namespace
            yaml.dump(cm, f, default_flow_style=False)
            f.write("---\n")

        # Deployment
        deployment["metadata"]["namespace"] = namespace
        yaml.dump(deployment, f, default_flow_style=False)
        f.write("---\n")

        # Service
        service["metadata"]["namespace"] = namespace
        yaml.dump(service, f, default_flow_style=False)


# CLI


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Generate NemoGuardrails manifest from server_configs")
    parser.add_argument("--run-dir", required=True, help="Run directory")
    parser.add_argument("--namespace", default="llm-serving", help="Kubernetes namespace")
    parser.add_argument("--name", default="asago-rec", help="CR/Deployment name")
    parser.add_argument("--mode", choices=["operator", "standalone"], default="operator", help="Generation mode")
    parser.add_argument(
        "--image", default=DEFAULT_IMAGE, help="Container image for standalone mode (default: %(default)s)"
    )
    parser.add_argument("--configs", nargs="*", help="Subset of config folder names (default: all)")
    parser.add_argument(
        "--key-secret", default="litellm-master-key", help="Secret name for API key (default: litellm-master-key)"
    )
    parser.add_argument("--out", help="Output YAML path (default: <run-dir>/deploy.yaml or deploy-standalone.yaml)")
    parser.add_argument("--cpu", default="4", help="CPU request/limit")
    parser.add_argument("--memory", default="16Gi", help="Memory request/limit")

    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir).resolve()
    server_configs_dir = run_dir / "server_configs"

    # Determine output path
    if args.out:
        out_path = Path(args.out)
    else:
        out_name = "deploy-standalone.yaml" if args.mode == "standalone" else "deploy.yaml"
        out_path = run_dir / out_name

    if not server_configs_dir.exists():
        print(f"Error: server_configs not found at {server_configs_dir}")
        return 1

    # Build ConfigMaps
    try:
        configmaps, config_id_to_cm_name = build_configmaps(
            server_configs_dir,
            args.configs,
        )
    except ValueError as e:
        print(f"Error: {e}")
        return 1

    if not config_id_to_cm_name:
        print(f"Error: No configs found in {server_configs_dir}")
        return 1

    if args.mode == "operator":
        cr = build_nemoguardrails_cr(args.name, config_id_to_cm_name, key_secret_name=args.key_secret)
        write_manifest(configmaps, cr, out_path, args.namespace)
    else:
        deployment = build_standalone_deployment(
            args.name,
            args.image,
            config_id_to_cm_name,
            args.cpu,
            args.memory,
            key_secret_name=args.key_secret,
        )
        service = build_standalone_service(args.name)
        write_standalone_manifest(configmaps, deployment, service, out_path, args.namespace)

    # Print summary
    print(f"[*] Generated {args.mode} manifest with {len(configmaps)} ConfigMap(s)")
    print(f"[*] Name: {args.name}")
    print(f"[*] Output: {out_path}")
    print(f"[*] Apply with: oc apply -f {out_path}")

    # Validate YAML
    try:
        with open(out_path) as f:
            docs = list(yaml.safe_load_all(f))
        print(f"[OK] YAML valid ({len(docs)} docs)")
    except Exception as e:
        print(f"[FAILED] YAML validation failed: {e}")
        return 1

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
