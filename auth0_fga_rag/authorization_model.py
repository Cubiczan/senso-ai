"""Auth0 FGA Authorization Model definition, validation, and helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Authorization Model — Auth0 FGA DSL
# ---------------------------------------------------------------------------

AUTHORIZATION_MODEL_YAML: str = """\
model
  schema 1.1

type user

type document
  relations
    define owner: [user]
    define editor: [user, manager#member] or owner
    define reader: [user, editor] or manager#member or public_reader
    define manager: [user] or manager#member

type department
  relations
    define member: [user]
    define head: [user]
"""

# ---------------------------------------------------------------------------
# Data classes for parsed model elements
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RelationDef:
    """A single relation inside an Auth0 FGA type definition."""

    name: str
    definition: str  # raw RHS of the `define` statement


@dataclass(frozen=True)
class TypeDef:
    """A single type in the Auth0 FGA authorization model."""

    name: str
    relations: tuple[RelationDef, ...] = ()


@dataclass
class AuthorizationModel:
    """Parsed representation of an Auth0 FGA authorization model."""

    schema_version: str = "1.1"
    types: dict[str, TypeDef] = field(default_factory=dict)

    def add_type(self, typedef: TypeDef) -> None:
        self.types[typedef.name] = typedef

    def get_relations(self, type_name: str) -> tuple[RelationDef, ...]:
        td = self.types.get(type_name)
        return td.relations if td else ()

    def validate(self) -> list[str]:
        """Return a list of validation errors (empty list means valid)."""
        errors: list[str] = []
        required_types = {"user", "document", "department"}
        for req in required_types:
            if req not in self.types:
                errors.append(f"Missing required type: {req}")
        for tname, td in self.types.items():
            if not td.relations and tname != "user":
                errors.append(f"Type '{tname}' has no relations defined")
        return errors


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_RELATION_RE = re.compile(r"define\s+(\w+):\s+(.+)", re.IGNORECASE)
_TYPE_RE = re.compile(r"^type\s+(\w+)$", re.MULTILINE)


def parse_authorization_model(yaml_text: str = AUTHORIZATION_MODEL_YAML) -> AuthorizationModel:
    """Parse the Auth0 FGA DSL into an *AuthorizationModel* object."""
    model = AuthorizationModel()

    version_match = re.search(r"schema\s+([\d.]+)", yaml_text)
    if version_match:
        model.schema_version = version_match.group(1)

    type_names = _TYPE_RE.findall(yaml_text)
    for tname in type_names:
        relations: list[RelationDef] = []
        # Grab the block between `type <name>` and the next `type` or EOF
        block_match = re.search(
            rf"(?:^type {tname}\s*\nrelations\s*\n)((?:\s+define .+\n?)+)",
            yaml_text,
            re.MULTILINE,
        )
        if block_match:
            for line in block_match.group(1).splitlines():
                m = _RELATION_RE.match(line.strip())
                if m:
                    relations.append(RelationDef(name=m.group(1), definition=m.group(2)))
        model.add_type(TypeDef(name=tname, relations=tuple(relations)))

    return model


def validate_model(yaml_text: str = AUTHORIZATION_MODEL_YAML) -> tuple[bool, list[str]]:
    """Validate the model and return *(is_valid, errors)*."""
    model = parse_authorization_model(yaml_text)
    errors = model.validate()
    return (len(errors) == 0, errors)


def model_summary(yaml_text: str = AUTHORIZATION_MODEL_YAML) -> str:
    """Return a human-readable summary of the authorization model."""
    model = parse_authorization_model(yaml_text)
    lines = [
        f"Authorization Model (schema {model.schema_version})",
        "=" * 50,
    ]
    for tname, td in model.types.items():
        lines.append(f"\n  type {tname}")
        if td.relations:
            for rel in td.relations:
                lines.append(f"    define {rel.name}: {rel.definition}")
        else:
            lines.append("    (no relations)")
    return "\n".join(lines)
