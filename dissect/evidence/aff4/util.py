from __future__ import annotations

import datetime
import re
import urllib.parse
from enum import Enum
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from collections.abc import Iterator

NS_XSD = "http://www.w3.org/2001/XMLSchema#"
NS_RDF = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
NS_AFF4 = "http://aff4.org/Schema#"


class CompressionMethod(Enum):
    ZLIB = "https://www.ietf.org/rfc/rfc1950.txt"
    DEFLATE = "https://tools.ietf.org/html/rfc1951"
    SNAPPY = "http://code.google.com/p/snappy/"
    SNAPPY2 = "https://github.com/google/snappy"
    LZ4 = "https://code.google.com/p/lz4/"
    STORED = "http://aff4.org/Schema#NullCompressor"


def parse_turtle(fh: TextIO) -> dict[str, str]:
    """Poor mans turtle parser. Save the turtles 🐢.

    Args:
        fh: A text file-like object containing turtle data.
    """
    objects = {}
    prefixes = {}
    base = None

    parts = []
    for line in fh:
        if not (line := line.strip()):
            continue

        # First construct a full statement
        if line.endswith("."):
            parts.append(line[:-1])
            full_statement = " ".join(parts)
            parts = []

            # Process a statement
            if full_statement.startswith("@prefix"):
                _, prefix, uri = full_statement.split(maxsplit=2)
                prefixes[prefix] = uri.rstrip(".").strip()[1:-1]
            elif full_statement.startswith("@base"):
                _, uri = full_statement.split(maxsplit=1)
                base = uri.rstrip(".").strip()[1:-1]
            else:
                subject = None
                for statement in _iter_statements(full_statement, ";"):
                    if subject is None:
                        subject, predicate, object = statement.split(maxsplit=2)
                        subject = _explode_prefix(subject.strip(), prefixes)

                        if subject.startswith("<") and subject.endswith(">"):
                            subject = _resolve_iri(subject[1:-1], base)
                    else:
                        predicate, object = statement.split(maxsplit=1)

                    predicate = predicate.strip()
                    object = object.strip()

                    if predicate == "a":
                        predicate = f"{NS_RDF}type"

                    predicate = _explode_prefix(predicate, prefixes)

                    if len(object := [_parse_object(obj, prefixes, base) for obj in _iter_statements(object, ",")]) == 1:
                        object = object[0]

                    if subject not in objects:
                        objects[subject] = {}

                    if predicate in objects[subject]:
                        raise ValueError(f"Duplicate predicate {predicate} for subject {subject}")

                    objects[subject][predicate] = object
        else:
            parts.append(line)

    return objects


def _iter_statements(statement: str, delimiter: str) -> Iterator[str]:
    """Iterate over statements separated by a delimiter."""
    current = []
    escape = False
    in_literal = False
    in_uri = False

    for c in statement:
        if c == "\\" and not escape:
            escape = True

        elif escape:
            escape = False
            current.append(c)

        elif c in "'\"":
            in_literal = not in_literal
            current.append(c)

        elif c == "<>" and not in_literal:
            in_uri = not in_uri
            current.append(c)

        elif c == delimiter and not in_literal and not in_uri:
            yield "".join(current).strip()
            current = []

        else:
            current.append(c)

    if current:
        yield "".join(current).strip()


_OBJECT_PARSERS = {
    f"{NS_XSD}int": int,
    f"{NS_XSD}long": int,
    f"{NS_XSD}integer": int,
    f"{NS_XSD}boolean": lambda v: v.lower() in ("true", "1"),
    f"{NS_XSD}hexBinary": bytes.fromhex,
    f"{NS_XSD}dateTime": lambda v: datetime.datetime.strptime(v, "%Y-%m-%dT%H:%M:%S.%f%z"),
}


def _parse_object(value: str, prefixes: dict[str, str], base: str | None = None) -> str | int | bool | float | bytes | datetime.datetime:
    """Parse a turtle object value."""
    value, _, type = value.partition("^^")

    value = f"<{_explode_prefix(value, prefixes)}>" if value in prefixes else _explode_prefix(value, prefixes)
    type = _explode_prefix(type, prefixes)

    if value.startswith("<") and value.endswith(">"):
        # Resolve (possibly relative) IRI references against the base IRI
        value = f"<{_resolve_iri(value[1:-1], base)}>"
    elif value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    elif not type:
        # A bare literal carries an implicit datatype based on its lexical form (integer, decimal, double
        # or boolean). Resolve it here so callers get a native Python value instead of a string.
        return _parse_bare_literal(value)

    if parser := _OBJECT_PARSERS.get(type):
        return parser(value)

    return value


_RE_INTEGER = re.compile(r"^[+-]?\d+$")
_RE_DOUBLE = re.compile(r"^[+-]?(\d+\.\d*|\.\d+|\d+)[eE][+-]?\d+$")
_RE_DECIMAL = re.compile(r"^[+-]?(\d+\.\d*|\.\d+)$")


def _parse_bare_literal(value: str) -> str | int | bool | float:
    """Parse a bare (undatatyped) turtle literal into its native Python value."""
    if value in ("true", "false"):
        return value == "true"
    if _RE_INTEGER.match(value):
        return int(value)
    if _RE_DOUBLE.match(value) or _RE_DECIMAL.match(value):
        return float(value)
    return value


_RE_ABSOLUTE_IRI = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)


def _resolve_iri(value: str, base: str | None) -> str:
    """Resolve a (possibly relative) turtle IRI reference against the base IRI.

    Absolute IRIs (those with a scheme, e.g. ``aff4://...``) are returned unchanged. Relative references,
    including the empty reference ``<>`` which denotes the base IRI itself, are resolved against ``base``.
    """
    if base is None or _RE_ABSOLUTE_IRI.match(value):
        return value
    return urllib.parse.urljoin(base, value) if value else base


def _explode_prefix(value: str, prefixes: dict[str, str]) -> str:
    """Expand a prefixed turtle value to its full URI."""
    for prefix, uri in prefixes.items():
        if value.startswith(prefix):
            return value.replace(prefix, uri, 1)
    return value
