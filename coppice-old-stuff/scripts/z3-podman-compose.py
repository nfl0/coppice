#!/usr/bin/env python3
"""Merge Z3's official Compose files while preserving Compose !override."""

import sys
from pathlib import Path

import yaml


class Override:
    def __init__(self, value):
        self.value = value


class Loader(yaml.SafeLoader):
    pass


def construct_override(loader, node):
    if isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node, deep=True)
    else:
        value = loader.construct_scalar(node)
    return Override(value)


Loader.add_constructor("!override", construct_override)


def merge(base, overlay, path=()):
    if isinstance(overlay, Override):
        return overlay.value
    if isinstance(base, dict) and isinstance(overlay, dict):
        result = dict(base)
        for key, value in overlay.items():
            result[key] = merge(result[key], value, path + (key,)) if key in result else value
        return result
    if isinstance(base, list) and isinstance(overlay, list):
        # Compose replaces shell commands and healthcheck commands; other
        # ordinary sequences append unless Z3 explicitly marks !override.
        return overlay if path[-2:] == ("healthcheck", "test") else base + overlay
    return overlay


if len(sys.argv) != 4:
    raise SystemExit("usage: z3-podman-compose.py BASE OVERLAY OUTPUT")

with Path(sys.argv[1]).open(encoding="utf-8") as source:
    base = yaml.load(source, Loader=Loader)
with Path(sys.argv[2]).open(encoding="utf-8") as source:
    overlay = yaml.load(source, Loader=Loader)
result = merge(base, overlay)
# This playground intentionally starts only the Zcash services it exercises.
# Removing unrelated Z3 services also avoids podman-compose trying to recreate
# optional rpc-router/monitoring containers that were never started.
required_services = {"zebra", "cookie-permissions", "zaino", "zallet"}
result["services"] = {
    name: service
    for name, service in result.get("services", {}).items()
    if name in required_services
}
# Podman intentionally refuses unresolved Docker short names on installations
# without a registries.conf search list. Z3's image names use Docker semantics.
for service in result.get("services", {}).values():
    image = service.get("image")
    if image and "$" in image:
        continue
    if image and "/" not in image:
        service["image"] = "docker.io/library/" + image
    elif image and "." not in image.split("/", 1)[0]:
        service["image"] = "docker.io/" + image
with Path(sys.argv[3]).open("w", encoding="utf-8") as target:
    yaml.safe_dump(result, target, sort_keys=False)
