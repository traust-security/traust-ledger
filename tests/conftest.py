from __future__ import annotations

import sys

import pytest


@pytest.fixture(autouse=True)
def _no_import_graph_mutation():
    """Fail the test that breaks parent/submodule attribute bindings.

    Checking `sys.modules` is not enough and was the first thing tried: a test
    that deletes entries, re-imports, then puts the *original* objects back
    leaves `sys.modules` pristine while the parent package object has lost the
    attribute the re-import rebound elsewhere. What breaks later is attribute
    resolution — `traust_ledger.auth` no longer having `.config` — so that is what
    this checks.
    """
    before = []
    for name, module in list(sys.modules.items()):
        if not name.startswith("traust_ledger.") or module is None:
            continue
        parent_name, _, child = name.rpartition(".")
        parent = sys.modules.get(parent_name)
        if parent is not None and getattr(parent, child, None) is module:
            before.append((parent_name, child, module))
    yield
    damaged = []
    for parent_name, child, module in before:
        parent = sys.modules.get(parent_name)
        if parent is None:
            damaged.append(f"{parent_name} (package gone)")
        elif getattr(parent, child, None) is not module:
            damaged.append(f"{parent_name}.{child}")
    assert not damaged, (
        "this test left the import graph damaged: "
        + ", ".join(sorted(damaged))
        + ". Re-importing a package does not rebind submodule attributes on its "
        "parent, so restoring sys.modules is not enough — unrelated later tests "
        "then fail to resolve dotted monkeypatch targets. Do import-graph "
        "manipulation in a subprocess instead."
    )
