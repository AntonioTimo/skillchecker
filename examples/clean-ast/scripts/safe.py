"""Safe data helper (negative fixture — the AST pass must NOT flag any of this)."""
import json
import subprocess

import yaml


def list_dir():
    # argument list, no shell=True, with a timeout — safe by construction
    return subprocess.run(["ls", "-l"], capture_output=True, timeout=10)


def parse_json(text):
    return json.loads(text)


def read_yaml(text):
    return yaml.safe_load(text)


def get_name(obj):
    return getattr(obj, "name", None)
