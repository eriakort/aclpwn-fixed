#!/usr/bin/env python3
"""
Direct BloodHound JSON importer for Neo4j 4.x
Handles ConstraintAlreadyExists gracefully, works without auth.
Usage: python3 bh_import.py /path/to/*.json
"""
import json
import sys
import glob
from neo4j import GraphDatabase

BOLT = "bolt://localhost:7687"
USER = "neo4j"
PASS = ""

# Map BloodHound meta.type -> Neo4j labels
TYPE_LABELS = {
    "users":      ("User", "Base"),
    "groups":     ("Group", "Base"),
    "computers":  ("Computer", "Base"),
    "domains":    ("Domain", "Base"),
    "gpos":       ("GPO", "Base"),
    "ous":        ("OU", "Base"),
    "containers": ("Container", "Base"),
}

def upsert_node(tx, objectid, labels, props):
    label_str = ":".join(labels)
    q = (
        f"MERGE (n:Base {{objectid: $oid}}) "
        f"SET n:{label_str} "
        f"SET n += $props "
        f"SET n.objectid = $oid"
    )
    tx.run(q, oid=objectid, props=props)

def upsert_ace(tx, src_sid, dst_sid, right):
    q = (
        "MATCH (src:Base {objectid: $src}) "
        "MATCH (dst:Base {objectid: $dst}) "
        "MERGE (src)-[r:" + right + "]->(dst)"
    )
    tx.run(q, src=src_sid, dst=dst_sid)

def upsert_memberof(tx, member_sid, group_sid):
    q = (
        "MATCH (m:Base {objectid: $member}) "
        "MATCH (g:Base {objectid: $group}) "
        "MERGE (m)-[:MemberOf]->(g)"
    )
    tx.run(q, member=member_sid, group=group_sid)

def ensure_constraints(driver):
    constraints = [
        "CREATE CONSTRAINT base_objectid_unique IF NOT EXISTS FOR (b:Base) REQUIRE b.objectid IS UNIQUE",
    ]
    with driver.session() as session:
        for c in constraints:
            try:
                session.run(c)
                print("[+] Constraint created/verified")
            except Exception as e:
                print(f"[~] Constraint note: {e}")

def import_file(driver, path):
    with open(path) as f:
        data = json.load(f)

    meta = data.get("meta", {})
    obj_type = meta.get("type", "")
    items = data.get("data", [])

    labels = TYPE_LABELS.get(obj_type)
    if not labels:
        print(f"[!] Unknown type '{obj_type}' in {path}, skipping")
        return

    print(f"[*] Importing {len(items)} {obj_type} from {path}")
    node_count = 0
    ace_count = 0

    with driver.session() as session:
        for item in items:
            oid = item.get("ObjectIdentifier")
            if not oid:
                continue
            props = item.get("Properties", {})
            # Ensure name is set
            if "name" not in props and oid:
                props["name"] = oid

            try:
                session.write_transaction(upsert_node, oid, labels, props)
                node_count += 1
            except Exception as e:
                print(f"  [!] Node error ({oid}): {e}")

            # Import ACEs
            for ace in item.get("Aces", []):
                right = ace.get("RightName", "").replace(" ", "")
                principal_sid = ace.get("PrincipalSID")
                if not right or not principal_sid:
                    continue
                # Skip rights aclpwn doesn't use
                allowed = {"GenericAll","GenericWrite","WriteOwner","WriteDacl",
                           "Owns","AddMember","GetChanges","GetChangesAll",
                           "AllExtendedRights","DCSync","ForceChangePassword"}
                if right not in allowed:
                    continue
                try:
                    session.write_transaction(upsert_ace, principal_sid, oid, right)
                    ace_count += 1
                except Exception as e:
                    pass  # Usually missing source node, fine

            # Import group memberships
            for member in item.get("Members", []):
                member_sid = member.get("ObjectIdentifier")
                if member_sid:
                    try:
                        session.write_transaction(upsert_memberof, member_sid, oid)
                    except Exception:
                        pass

        print(f"    -> {node_count} nodes, {ace_count} ACEs written")

def main():
    paths = []
    for arg in sys.argv[1:]:
        paths.extend(glob.glob(arg))

    if not paths:
        print("Usage: python3 bh_import.py /path/to/bloodhound/*.json")
        sys.exit(1)

    print(f"[*] Connecting to {BOLT}")
    driver = GraphDatabase.driver(BOLT, auth=(USER, PASS))

    ensure_constraints(driver)

    for path in sorted(paths):
        import_file(driver, path)

    driver.close()
    print("[+] Import complete")

if __name__ == "__main__":
    main()
