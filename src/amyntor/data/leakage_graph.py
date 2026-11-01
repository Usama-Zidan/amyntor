"""Bounded disk-backed graph operations. No split assignments or identity inference."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import time
from pathlib import Path

from amyntor.data.leakage_contract import AuditLimit, LeakageError, Limits

DDL = """
CREATE TABLE nodes(id INTEGER PRIMARY KEY,org TEXT,incident TEXT,retained INTEGER,
 grade TEXT,alerts INTEGER,p_all INTEGER,p_retained INTEGER,p_sensitivity INTEGER);
CREATE UNIQUE INDEX node_identity ON nodes(org,incident);
CREATE TABLE edges(a INTEGER,b INTEGER,kind TEXT,PRIMARY KEY(a,b,kind)) WITHOUT ROWID;
CREATE TABLE tokens(node INTEGER,field TEXT,token BLOB,eligible INTEGER,ambiguous INTEGER,
 PRIMARY KEY(node,field,token)) WITHOUT ROWID;
CREATE TABLE sources(node INTEGER,source TEXT,PRIMARY KEY(node,source)) WITHOUT ROWID;
CREATE TABLE features(node INTEGER,alert TEXT,field TEXT,value BLOB,empty INTEGER,
 null_like INTEGER,sentinel INTEGER,PRIMARY KEY(node,alert,field,value)) WITHOUT ROWID;
CREATE TABLE outcomes(node INTEGER,field TEXT,value BLOB,empty INTEGER,
 PRIMARY KEY(node,field,value)) WITHOUT ROWID;
CREATE TABLE pairs(a INTEGER,b INTEGER,shared INTEGER DEFAULT 0,denominator INTEGER DEFAULT 0,
 discriminative INTEGER DEFAULT 0,flagged INTEGER DEFAULT 0,pair_id TEXT,decision TEXT,
 universe TEXT DEFAULT 'all_verified_identity',
 PRIMARY KEY(a,b)) WITHOUT ROWID;
CREATE TABLE findings(id TEXT PRIMARY KEY,kind TEXT,scope TEXT,support INTEGER,detail TEXT,
 resolution TEXT,evidence TEXT) WITHOUT ROWID;
CREATE TABLE reviews(id TEXT PRIMARY KEY,kind TEXT,decision TEXT,evidence TEXT,rationale TEXT) WITHOUT ROWID;
"""


class Budget:
    """Concrete per-invocation watchdog shared by ingestion, graph and SQL work."""

    def __init__(self, scratch: Path, limits: Limits) -> None:
        self.scratch, self.limits = scratch, limits
        self.started = time.monotonic()
        self.last_disk_check = 0.0
        self.maximum_visible_bytes = 0
        self.candidate_attempts = 0
        self.failure: str | None = None

    def check(self, *, candidate: bool = False) -> None:
        if candidate:
            if self.candidate_attempts >= self.limits.candidate_attempts:
                raise AuditLimit("candidate_attempt_limit")
            self.candidate_attempts += 1
        now = time.monotonic()
        if now - self.started > self.limits.max_seconds:
            raise AuditLimit("time_limit")
        if now - self.last_disk_check >= 0.5:
            self.last_disk_check = now
            if shutil.disk_usage(self.scratch).free < self.limits.minimum_free_bytes:
                raise AuditLimit("scratch_free_space_floor")
            visible = sum(
                p.stat().st_size for p in self.scratch.rglob("*") if p.is_file()
            )
            self.maximum_visible_bytes = max(visible, self.maximum_visible_bytes)
            if visible > self.limits.scratch_bytes:
                raise AuditLimit("visible_scratch_limit")

    def progress(self) -> int:
        try:
            self.check()
        except AuditLimit as error:
            self.failure = str(error)
            return 1
        return 0


def open_store(
    scratch: Path, g3: Path, budget: Budget
) -> tuple[sqlite3.Connection, str]:
    connection = sqlite3.connect(scratch / "audit.sqlite3", uri=True)
    previous = connection.execute("PRAGMA temp_store_directory").fetchone()
    old_temp = str(previous[0]) if previous else ""
    try:
        temp = scratch / "sqlite-temp"
        temp.mkdir()
        quoted = str(temp.resolve()).replace("'", "''")
        connection.execute(f"PRAGMA temp_store_directory='{quoted}'")
        if connection.execute("PRAGMA temp_store_directory").fetchone() != (
            str(temp.resolve()),
        ):
            raise LeakageError("SQLite temporary-file placement unavailable")
        connection.execute("PRAGMA temp_store=FILE")
        connection.execute("PRAGMA mmap_size=0")
        connection.execute("PRAGMA threads=1")
        connection.execute("PRAGMA synchronous=OFF")
        connection.execute(f"PRAGMA cache_size=-{budget.limits.cache_mib * 1024}")
        pages = connection.execute("PRAGMA page_size").fetchone()[0]
        connection.execute(
            f"PRAGMA max_page_count={max(1, budget.limits.scratch_bytes // pages)}"
        )
        connection.execute(
            "ATTACH DATABASE ? AS src",
            ((g3 / "incidents.sqlite3").resolve().as_uri() + "?mode=ro",),
        )
        connection.set_progress_handler(budget.progress, 10000)
        connection.executescript(DDL)
    except BaseException:
        close_store(connection, old_temp)
        raise
    return connection, old_temp


def close_store(connection: sqlite3.Connection, old_temp: str) -> None:
    connection.set_progress_handler(None, 0)
    try:
        connection.rollback()
        connection.execute(
            "PRAGMA temp_store_directory='" + old_temp.replace("'", "''") + "'"
        )
    finally:
        connection.close()


def summarize_components(
    connection: sqlite3.Connection, budget: Budget
) -> dict[str, object]:
    flatten(connection, budget)
    component_ids(connection, budget)
    connection.executescript("""
        CREATE TABLE component_composition AS SELECT p_all AS root,COUNT(*) AS incidents,
          SUM(retained) AS retained_incidents,COUNT(DISTINCT org) AS organizations,
          COUNT(DISTINCT grade) AS known_dispositions,
          SUM(CASE WHEN grade='TruePositive' THEN 1 ELSE 0 END) AS true_positive,
          SUM(CASE WHEN grade='BenignPositive' THEN 1 ELSE 0 END) AS benign_positive,
          SUM(CASE WHEN grade='FalsePositive' THEN 1 ELSE 0 END) AS false_positive
          FROM nodes GROUP BY p_all;
        CREATE TABLE component_sources AS SELECT n.p_all AS root,s.source,COUNT(*) AS incidents
          FROM sources s JOIN nodes n ON n.id=s.node GROUP BY n.p_all,s.source;
    """)
    return {
        "all_context_components": connection.execute(
            "SELECT COUNT(*) FROM component_ids"
        ).fetchone()[0],
        "unique_typed_hard_edges": connection.execute(
            "SELECT COUNT(*) FROM edges"
        ).fetchone()[0],
        "quarantined_incidents": connection.execute(
            "SELECT COUNT(*) FROM nodes WHERE retained=0"
        ).fetchone()[0],
        "components_with_quarantine_bridges": component_statistics(connection, "p_all"),
        "components_without_quarantine_bridges": component_statistics(
            connection, "p_retained"
        ),
        "code_equality_sensitivity_not_confirmed_identity": component_statistics(
            connection, "p_sensitivity"
        ),
        "full_context_incidents": connection.execute(
            "SELECT COUNT(*) FROM nodes"
        ).fetchone()[0],
        "retained_incidents": connection.execute(
            "SELECT COUNT(*) FROM nodes WHERE retained=1"
        ).fetchone()[0],
        "quarantine_bridged_retained_components": connection.execute(
            "SELECT COALESCE(SUM(c-1),0) FROM (SELECT p_all,COUNT(DISTINCT p_retained) AS c FROM nodes WHERE retained=1 GROUP BY p_all)"
        ).fetchone()[0],
        "mixed_grade_components": connection.execute(
            "SELECT COUNT(*) FROM (SELECT p_all FROM nodes WHERE retained=1 GROUP BY p_all HAVING COUNT(DISTINCT grade)>1)"
        ).fetchone()[0],
        "cross_organization_components": connection.execute(
            "SELECT COUNT(*) FROM (SELECT p_all FROM nodes GROUP BY p_all HAVING COUNT(DISTINCT org)>1)"
        ).fetchone()[0],
    }


def root(
    connection: sqlite3.Connection, node: int, column: str, budget: Budget | None = None
) -> int:
    if column not in {"p_all", "p_retained", "p_sensitivity"}:
        raise ValueError("Unsupported component variant")
    current = node
    while True:
        if budget is not None:
            budget.check()
        parent = connection.execute(
            f"SELECT {column} FROM nodes WHERE id=?", (current,)
        ).fetchone()[0]
        if parent == current:
            return current
        grandparent = connection.execute(
            f"SELECT {column} FROM nodes WHERE id=?", (parent,)
        ).fetchone()[0]
        connection.execute(
            f"UPDATE nodes SET {column}=? WHERE id=?", (grandparent, current)
        )
        current = grandparent


def union(
    connection: sqlite3.Connection,
    a: int,
    b: int,
    column: str,
    budget: Budget | None = None,
) -> None:
    left, right = (
        root(connection, a, column, budget),
        root(connection, b, column, budget),
    )
    if left != right:
        connection.execute(
            f"UPDATE nodes SET {column}=? WHERE id=?",
            (min(left, right), max(left, right)),
        )


def hard_edge(
    connection: sqlite3.Connection,
    a: int,
    b: int,
    kind: str,
    budget: Budget | None = None,
) -> None:
    a, b = min(a, b), max(a, b)
    connection.execute("INSERT OR IGNORE INTO edges VALUES (?,?,?)", (a, b, kind))
    union(connection, a, b, "p_all", budget)
    union(connection, a, b, "p_sensitivity", budget)
    if (
        connection.execute(
            "SELECT SUM(retained) FROM nodes WHERE id IN (?,?)", (a, b)
        ).fetchone()[0]
        == 2
    ):
        union(connection, a, b, "p_retained", budget)


def shared_alert_graph(
    connection: sqlite3.Connection, budget: Budget
) -> dict[str, int]:
    """Linear stars, with a separate retained star for each shared alert."""
    previous: tuple[str, str] | None = None
    first = first_retained = 0
    groups = shared = memberships = retained_memberships = 0
    group_size = 0
    for org, alert, node, retained in connection.execute(
        "SELECT m.org,m.alert,n.id,n.retained FROM src.incident_alerts m "
        "JOIN nodes n ON n.org=m.org AND n.incident=m.incident ORDER BY m.org,m.alert,n.id"
    ):
        budget.check()
        if previous != (org, alert):
            shared += int(group_size > 1)
            groups += 1
            first, first_retained, group_size = node, 0, 0
            previous = (org, alert)
        elif node != first:
            hard_edge(connection, first, node, "scoped_alert", budget)
        if retained:
            if first_retained:
                union(connection, first_retained, node, "p_retained", budget)
            else:
                first_retained = node
            retained_memberships += 1
        memberships += 1
        group_size += 1
        if memberships % budget.limits.batch_rows == 0:
            connection.commit()
    shared += int(group_size > 1)
    connection.commit()
    return {
        "scoped_alerts": groups,
        "reused_scoped_alerts": shared,
        "local_memberships": memberships,
        "retained_local_memberships": retained_memberships,
    }


def flatten(connection: sqlite3.Connection, budget: Budget) -> None:
    for node, retained in connection.execute(
        "SELECT id,retained FROM nodes ORDER BY id"
    ):
        budget.check()
        for column in (
            "p_all",
            "p_sensitivity",
            *(("p_retained",) if retained else ()),
        ):
            connection.execute(
                f"UPDATE nodes SET {column}=? WHERE id=?",
                (root(connection, node, column, budget), node),
            )
        if node % budget.limits.batch_rows == 0:
            connection.commit()
    connection.commit()


def component_statistics(
    connection: sqlite3.Connection, column: str
) -> dict[str, object]:
    if column not in {"p_all", "p_retained", "p_sensitivity"}:
        raise ValueError("Unsupported component variant")
    connection.execute("DROP TABLE IF EXISTS component_sizes")
    connection.execute(
        f"CREATE TABLE component_sizes AS SELECT {column} AS root,COUNT(*) AS size FROM nodes WHERE retained=1 GROUP BY {column}"
    )
    count, total, maximum = connection.execute(
        "SELECT COUNT(*),COALESCE(SUM(size),0),COALESCE(MAX(size),0) FROM component_sizes"
    ).fetchone()

    def quantile(offset: int) -> int:
        row = connection.execute(
            "SELECT size FROM component_sizes ORDER BY size LIMIT 1 OFFSET ?", (offset,)
        ).fetchone()
        return int(row[0]) if row else 0

    singleton_count = connection.execute(
        "SELECT COUNT(*) FROM component_sizes WHERE size=1"
    ).fetchone()[0]
    return {
        "retained_components": count,
        "retained_incidents": total,
        "singleton_components": singleton_count,
        "size": {
            "min": quantile(0),
            "median": (quantile((count - 1) // 2) + quantile(count // 2)) / 2
            if count
            else 0,
            "p95": quantile(max(0, (95 * count + 99) // 100 - 1)),
            "max": maximum,
        },
        "largest_retained_fraction": maximum / total if total else 0,
        "singleton_fraction": singleton_count / count if count else 0,
        "components_over_20_percent_global_retained": connection.execute(
            "SELECT COUNT(*) FROM component_sizes WHERE size*5>?", (total,)
        ).fetchone()[0],
    }


def component_ids(connection: sqlite3.Connection, budget: Budget) -> None:
    connection.execute(
        "CREATE TABLE component_ids(root INTEGER PRIMARY KEY,digest TEXT)"
    )
    previous = 0
    digest = hashlib.sha256()
    first = True
    for component, org, incident in connection.execute(
        "SELECT p_all,org,incident FROM nodes ORDER BY p_all,org,incident"
    ):
        budget.check()
        if previous != component:
            if previous:
                digest.update(b"]")
                connection.execute(
                    "INSERT INTO component_ids VALUES (?,?)",
                    (previous, digest.hexdigest()),
                )
            previous, digest, first = component, hashlib.sha256(b"["), True
        if not first:
            digest.update(b",")
        digest.update(
            json.dumps(
                [org, incident], ensure_ascii=False, separators=(",", ":")
            ).encode()
        )
        first = False
    if previous:
        digest.update(b"]")
        connection.execute(
            "INSERT INTO component_ids VALUES (?,?)", (previous, digest.hexdigest())
        )
    connection.commit()
