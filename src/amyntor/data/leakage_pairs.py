"""Deterministic label-blind identity tokens and disk-backed exact Jaccard candidates."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from itertools import combinations
from pathlib import Path
from typing import cast

from amyntor.data.leakage_contract import AuditConfig, Identifier, LeakageError
from amyntor.data.leakage_graph import Budget, hard_edge, root
from amyntor.data.schema_contract import fingerprint


def identifier_token(
    rule: Identifier, org: str, value: str
) -> tuple[bytes, bool, bool] | None:
    if not value or value in rule.verified_sentinels:
        return None
    ambiguous = (
        rule.status != "VERIFIED"
        or rule.scope == "unresolved"
        or value in rule.ambiguous_values
    )
    namespace = org if rule.scope == "organization" else rule.scope
    token = hashlib.sha256(
        json.dumps([rule.field, namespace, value], separators=(",", ":")).encode()
    ).digest()
    return token, rule.copy_eligible and not ambiguous, ambiguous


def find_pairs(
    connection: sqlite3.Connection, config: AuditConfig, budget: Budget
) -> dict[str, int]:
    maximum = cast(int, config.rules["discriminative_max_incidents"])
    connection.executescript("""
        CREATE INDEX IF NOT EXISTS token_postings ON tokens(field,token,node);
        CREATE TABLE token_degrees AS SELECT field,token,COUNT(*) AS degree FROM tokens
          WHERE eligible=1 GROUP BY field,token;
        CREATE UNIQUE INDEX token_degree_keys ON token_degrees(field,token);
        CREATE TABLE token_sizes AS SELECT node,COUNT(*) AS size,SUM(field<>'AlertId') AS entity_size FROM tokens WHERE eligible=1 GROUP BY node;
        CREATE UNIQUE INDEX token_size_keys ON token_sizes(node);
    """)
    # Every qualifying pair must share >=2 discriminative tokens, hence this exact
    # inverted join is complete for the declared universe. Common tokens stay in
    # token_sizes and in the exact intersection/union denominator.
    for field, token in connection.execute(
        "SELECT field,token FROM token_degrees WHERE degree<=? ORDER BY field,token",
        (maximum,),
    ):
        budget.check()
        postings = connection.execute(
            "SELECT t.node FROM tokens t JOIN token_sizes s ON s.node=t.node "
            "WHERE t.field=? AND t.token=? AND t.eligible=1 AND s.size>=2 ORDER BY t.node LIMIT ?",
            (field, token, maximum + 1),
        ).fetchall()
        if len(postings) > maximum:
            raise LeakageError("Discriminative posting bound violated")
        for left, right in combinations(postings, 2):
            budget.check(candidate=True)
            connection.execute(
                "INSERT OR IGNORE INTO pairs(a,b) VALUES (?,?)", (left[0], right[0])
            )
            if budget.candidate_attempts % config.limits.batch_rows == 0:
                connection.commit()
    connection.commit()
    verified = flagged = exact = 0
    for a, b in connection.execute("SELECT a,b FROM pairs ORDER BY a,b"):
        budget.check()
        shared, discriminative, entity_shared, entity_discriminative = (
            connection.execute(
                "SELECT COUNT(*),COALESCE(SUM(d.degree<=?),0),"
                "COALESCE(SUM(a.field<>'AlertId'),0),COALESCE(SUM(a.field<>'AlertId' AND d.degree<=?),0) FROM tokens a "
                "JOIN tokens b USING(field,token) JOIN token_degrees d USING(field,token) "
                "WHERE a.node=? AND b.node=? AND a.eligible=1 AND b.eligible=1",
                (maximum, maximum, a, b),
            ).fetchone()
        )
        sizes, entity_sizes = connection.execute(
            "SELECT SUM(size),SUM(entity_size) FROM token_sizes WHERE node IN (?,?)",
            (a, b),
        ).fetchone()
        denominator = sizes - shared
        qualifies = discriminative >= 2 and shared * 10 >= denominator * 9
        universe = "all_verified_identity"
        if (
            not qualifies
            and entity_discriminative >= 2
            and entity_shared * 10 >= (entity_sizes - entity_shared) * 9
        ):
            shared, denominator, discriminative = (
                entity_shared,
                entity_sizes - entity_shared,
                entity_discriminative,
            )
            qualifies, universe = True, "verified_entity_only"
        keys = connection.execute(
            "SELECT org,incident FROM nodes WHERE id IN (?,?) ORDER BY org,incident",
            (a, b),
        ).fetchall()
        pair_id = fingerprint(["guide-g5-pair-v1", *[list(k) for k in keys]])
        connection.execute(
            "UPDATE pairs SET shared=?,denominator=?,discriminative=?,flagged=?,pair_id=?,universe=? WHERE a=? AND b=?",
            (
                shared,
                denominator,
                discriminative,
                int(qualifies),
                pair_id,
                universe,
                a,
                b,
            ),
        )
        verified += 1
        flagged += int(qualifies)
        exact += int(qualifies and shared == denominator)
        if verified % config.limits.batch_rows == 0:
            connection.commit()
    connection.execute("CREATE UNIQUE INDEX pair_identity ON pairs(pair_id)")
    connection.commit()
    return {
        "posting_pair_attempts": budget.candidate_attempts,
        "unique_pairs_verified": verified,
        "flagged_pairs": flagged,
        "exact_identity_set_candidates": exact,
        "eligible_incidents": connection.execute(
            "SELECT COUNT(*) FROM token_sizes WHERE size>=2"
        ).fetchone()[0],
        "common_verified_token_types": connection.execute(
            "SELECT COUNT(*) FROM token_degrees WHERE degree>?", (maximum,)
        ).fetchone()[0],
    }


def load_reviews(
    connection: sqlite3.Connection,
    path: Path | None,
    identity: str,
    config: AuditConfig,
    budget: Budget,
) -> None:
    if path is None:
        return
    if path.is_symlink() or not path.is_file():
        raise LeakageError("Regular private review file required")
    with path.open("rb") as stream:
        header = stream.readline(config.limits.review_line_bytes + 1)
        if len(header) > config.limits.review_line_bytes:
            raise LeakageError("Oversized review header")
        if json.loads(header) != {
            "gate": "G5_REVIEW",
            "audit_identity": identity,
            "label_blind": True,
        }:
            raise LeakageError(
                "Reviews must bind this exact label-blind audit identity"
            )
        while True:
            line = stream.readline(config.limits.review_line_bytes + 1)
            if not line:
                break
            budget.check()
            if len(line) > config.limits.review_line_bytes:
                raise LeakageError("Oversized review decision")
            doc: object = json.loads(line)
            if not isinstance(doc, dict):
                raise LeakageError("Invalid review decision")
            item = cast(dict[str, object], doc)
            if set(item) != {"id", "kind", "decision", "evidence", "rationale"} or any(
                not isinstance(v, str) or not v for v in item.values()
            ):
                raise LeakageError(
                    "Explicit evidence and rationale required for every review"
                )
            if item["kind"] == "pair":
                allowed = {
                    "CONFIRMED_COPY",
                    "CONSERVATIVE_DEPENDENCY",
                    "DISTINCT",
                    "DEFERRED",
                }
                found = connection.execute(
                    "SELECT 1 FROM pairs WHERE pair_id=? AND flagged=1", (item["id"],)
                ).fetchone()
            elif item["kind"] == "finding":
                allowed = {"EXPLAINED", "RETROSPECTIVE_LIMITATION", "BLOCK"}
                found = connection.execute(
                    "SELECT 1 FROM findings WHERE id=?", (item["id"],)
                ).fetchone()
            else:
                raise LeakageError("Unknown review kind")
            if item["decision"] not in allowed or not found:
                raise LeakageError(
                    "Review references an unsupported decision or unknown finding/pair"
                )
            try:
                connection.execute(
                    "INSERT INTO reviews VALUES (?,?,?,?,?)",
                    tuple(
                        item[k]
                        for k in ("id", "kind", "decision", "evidence", "rationale")
                    ),
                )
            except sqlite3.IntegrityError:
                raise LeakageError("Duplicate/conflicting review decisions") from None
    connection.commit()


def apply_reviews(connection: sqlite3.Connection, budget: Budget) -> dict[str, int]:
    for a, b, decision in connection.execute(
        "SELECT p.a,p.b,r.decision FROM pairs p JOIN reviews r ON r.id=p.pair_id WHERE r.kind='pair' ORDER BY p.a,p.b"
    ):
        budget.check()
        if decision in {"CONFIRMED_COPY", "CONSERVATIVE_DEPENDENCY"}:
            hard_edge(
                connection,
                a,
                b,
                "reviewed_copy"
                if decision == "CONFIRMED_COPY"
                else "reviewed_conservative",
                budget,
            )
        connection.execute(
            "UPDATE pairs SET decision=? WHERE a=? AND b=?", (decision, a, b)
        )
    # Exact transitive dependency proof, not a copy assertion or sample clearance.
    # Explicit DEFERRED decisions still block.
    for a, b in connection.execute(
        "SELECT a,b FROM pairs WHERE flagged=1 AND decision IS NULL ORDER BY a,b"
    ):
        budget.check()
        if root(connection, a, "p_all", budget) == root(connection, b, "p_all", budget):
            connection.execute(
                "UPDATE pairs SET decision='EXISTING_HARD_DEPENDENCY' WHERE a=? AND b=?",
                (a, b),
            )
    connection.execute(
        "UPDATE findings SET resolution=(SELECT decision FROM reviews r WHERE r.id=findings.id),evidence=(SELECT evidence FROM reviews r WHERE r.id=findings.id)"
    )
    connection.commit()
    return {
        "unresolved_pairs": connection.execute(
            "SELECT COUNT(*) FROM pairs WHERE flagged=1 AND (decision IS NULL OR decision='DEFERRED')"
        ).fetchone()[0],
        "unresolved_findings": connection.execute(
            "SELECT COUNT(*) FROM findings WHERE resolution IS NULL OR resolution='BLOCK'"
        ).fetchone()[0],
        "reviewed_pairs": connection.execute(
            "SELECT COUNT(*) FROM reviews WHERE kind='pair'"
        ).fetchone()[0],
        "pairs_resolved_by_verified_hard_path": connection.execute(
            "SELECT COUNT(*) FROM pairs WHERE decision='EXISTING_HARD_DEPENDENCY'"
        ).fetchone()[0],
    }
