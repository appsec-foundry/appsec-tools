import json
import os
from pathlib import Path
import tempfile

import yaml

from .errors import ConfigError, OutputError


class StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ConfigError("YAML aliases are not allowed.")
        self._depth = getattr(self, "_depth", 0) + 1
        if self._depth > 40:
            raise ConfigError("YAML is nested too deeply.")
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node, deep=False):
        result = {}
        for key, value in node.value:
            k = self.construct_object(key, deep=deep)
            if not isinstance(k, str) or k in result:
                raise ConfigError("Duplicate or non-string YAML keys.")
            result[k] = self.construct_object(value, deep=deep)
        return result


def read_yaml(path):
    try:
        with Path(path).open("rb") as f:
            data = f.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ConfigError("Configuration exceeds 1 MiB.")
        return yaml.load(data.decode("utf-8"), Loader=StrictLoader)
    except (OSError, UnicodeError, yaml.YAMLError, RecursionError):
        raise ConfigError("Configuration is unreadable or not valid safe YAML.") from None


class LiteralDumper(yaml.SafeDumper):
    pass


def _string(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)


LiteralDumper.add_representer(str, _string)


def yaml_bytes(value):
    return yaml.dump(value, Dumper=LiteralDumper, allow_unicode=True, sort_keys=False, width=100).encode("utf-8")


def atomic_write(path, data):
    path = Path(path)
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix=".harvest-", dir=path.parent)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    except OSError:
        raise OutputError("Output file could not be written atomically.") from None
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value):
    atomic_write(path, (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode())
