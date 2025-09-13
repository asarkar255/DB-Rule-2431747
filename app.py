from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Any, Dict, Tuple
import re

app = FastAPI(
    title="ABAP DB Operation Remediator for S/4HANA Obsolete FI/CO Tables (Note 2431747) — full-block rewrite"
)

# -------------------------
# Table mapping & config
# -------------------------
TABLE_MAPPING = {
    "BSIS": {"source": "ACDOCA", "view": True},
    "BSEG": {"source": "ACDOCA", "view": True},
    "BSAS": {"source": "ACDOCA", "view": True},
    "BSIK": {"source": "ACDOCA", "view": True},
    "BSAK": {"source": "ACDOCA", "view": True},
    "BSID": {"source": "ACDOCA", "view": True},
    "BSAD": {"source": "ACDOCA", "view": True},
    "GLT0": {"source": "ACDOCA", "view": True},
    "COEP": {"source": "ACDOCA", "view": True},
    "COSP": {"source": "ACDOCA", "view": True},
    "COSS": {"source": "ACDOCA", "view": True},
    "MLIT": {"source": "ACDOCA", "view": True},
    "ANEP": {"source": "ACDOCA", "view": True},
    "ANLP": {"source": "ACDOCA", "view": True},
}
NO_VIEW_TABLES = {"FAGLFLEXA", "FAGLFLEXT"}

OBSOLETE_TABLES = set(TABLE_MAPPING.keys()) | set(NO_VIEW_TABLES)

# -------------------------
# Regex
# -------------------------
# Match any complete SELECT ... .
SELECT_BLOCK_RE = re.compile(r"(?P<full>SELECT[\s\S]*?\.)", re.IGNORECASE)

# UPDATE, DELETE FROM, INSERT, MODIFY (statement-terminated)
UPDATE_RE = re.compile(r"(?P<full>UPDATE\s+\w+[\s\S]*?\.)", re.IGNORECASE)
DELETE_RE = re.compile(r"(?P<full>DELETE\s+FROM\s+\w+[\s\S]*?\.)", re.IGNORECASE)
INSERT_RE = re.compile(r"(?P<full>INSERT\s+\w+[\s\S]*?\.)", re.IGNORECASE)
MODIFY_RE = re.compile(r"(?P<full>MODIFY\s+\w+[\s\S]*?\.)", re.IGNORECASE)

# FROM / JOIN table capture:  FROM <tab> [AS alias]    JOIN <tab> [AS alias]
FROM_TBL_RE = re.compile(r"\bFROM\s+(?P<table>\w+)(?P<after>\s+(?:AS\s+)?\w+)?", re.IGNORECASE)
JOIN_TBL_RE = re.compile(r"\bJOIN\s+(?P<table>\w+)(?P<after>\s+(?:AS\s+)?\w+)?", re.IGNORECASE)

# Any obsolete table literal
LITERAL_TABLES_RE = re.compile(
    r"\b(" + "|".join(re.escape(t) for t in OBSOLETE_TABLES) + r")\b", re.IGNORECASE
)

# -------------------------
# Models
# -------------------------
class Finding(BaseModel):
    pgm_name: Optional[str] = None
    inc_name: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    class_implementation: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    issue_type: Optional[str] = None
    severity: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None
    original_block: Optional[str] = None
    remediated_block: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = None
    class_implementation: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code: Optional[str] = ""

# -------------------------
# Utils
# -------------------------
def line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1

def get_replacement_table(table: str) -> str:
    t_up = (table or "").upper()
    if t_up in NO_VIEW_TABLES:
        return "ACDOCA"
    if t_up in TABLE_MAPPING:
        return TABLE_MAPPING[t_up]["source"].split("/")[0]
    return table

def remediation_comment(table: str, stmt_type: str) -> str:
    t_up = (table or "").upper()
    if stmt_type in ("UPDATE", "INSERT", "MODIFY", "DELETE"):
        return "/* NOTE: Compatibility view cannot be used for write operations in S/4HANA. Use ACDOCA or source table directly. */"
    if t_up in NO_VIEW_TABLES:
        return f"/* NOTE: {t_up} is obsolete in S/4HANA. Use ACDOCA directly and map fields accordingly. */"
    if t_up in TABLE_MAPPING:
        src = TABLE_MAPPING[t_up]["source"]
        return f"/* NOTE: {t_up} is obsolete in S/4HANA. Adapt to ACDOCA or compatibility view (source: {src}). */"
    return ""

def inject_inline_comment(token_text: str, table: str, stmt_type: str) -> str:
    # Append a brief comment right after the table (keeps aliases intact)
    comment = remediation_comment(table, stmt_type)
    return (token_text + (" " + comment if comment else ""))

def replace_from_join_tables(block: str, stmt_type: str) -> Tuple[str, List[Dict[str, str]]]:
    """
    Replace obsolete tables in FROM and JOIN positions and inject short comments.
    Returns (new_block, changes_list)
    changes_list: [{"orig": "BSEG", "repl": "ACDOCA", "pos": <index>, "context": "FROM/JOIN"}]
    """
    changes: List[Dict[str, str]] = []
    out = block
    offset_shift = 0  # in case we later need positional details

    def _repl_func(m: re.Match, context: str) -> str:
        table = m.group("table")
        after = m.group("after") or ""
        t_up = table.upper()
        if t_up in OBSOLETE_TABLES:
            repl = get_replacement_table(table)
            token = f"{repl}{after}"
            token_with_cmt = inject_inline_comment(token, table, "SELECT")
            changes.append({"orig": t_up, "repl": repl, "context": context})
            return f"{context} {token_with_cmt}"
        # no change
        return m.group(0)

    # Replace FROM table
    out = FROM_TBL_RE.sub(lambda mm: _repl_func(mm, "FROM"), out, count=1)  # only the first FROM

    # Replace all JOIN tables
    out = JOIN_TBL_RE.sub(lambda mm: _repl_func(mm, "JOIN"), out)

    return out, changes

def remediate_select_block(block: str) -> Tuple[str, List[Dict[str, str]]]:
    """
    Produce a fully remediated SELECT block by replacing obsolete tables in FROM/JOIN.
    """
    new_block, changes = replace_from_join_tables(block, "SELECT")
    return new_block, changes

def remediate_other_block(stmt_text: str, stmt_type: str) -> Tuple[str, Optional[str]]:
    """
    Rewrite UPDATE/DELETE/INSERT/MODIFY for obsolete table and return (new_stmt, table_if_changed).
    """
    # Extract table following verb (for DELETE might be "DELETE FROM <table>")
    if stmt_type.upper() == "DELETE":
        m = re.search(r"\bDELETE\s+FROM\s+(\w+)", stmt_text, re.IGNORECASE)
    else:
        m = re.search(rf"\b{stmt_type}\s+(\w+)", stmt_text, re.IGNORECASE)
    if not m:
        return stmt_text, None

    table = m.group(1)
    t_up = table.upper()
    if t_up not in OBSOLETE_TABLES:
        return stmt_text, None

    repl = get_replacement_table(table)
    comment = remediation_comment(table, stmt_type.upper())
    if stmt_type.upper() == "DELETE":
        new = re.sub(rf"\bDELETE\s+FROM\s+{re.escape(table)}\b",
                     f"DELETE FROM {repl} {comment}", stmt_text, flags=re.IGNORECASE)
    else:
        new = re.sub(rf"\b{stmt_type}\s+{re.escape(table)}\b",
                     f"{stmt_type} {repl} {comment}", stmt_text, flags=re.IGNORECASE)
    return new, t_up

def snippet_at(text: str, start: int, end: int) -> str:
    # Keep previous behavior for quick context; now we also add original_block separately
    s = max(0, start - 60)
    e = min(len(text), end + 60)
    return text[s:e].replace("\n", "\\n")

def apply_span_replacements(source: str, repls: List[Tuple[Tuple[int, int], str]]) -> str:
    """
    Apply non-overlapping replacements from the end towards the start.
    repls: [((start, end), replacement_text), ...]
    """
    out = source
    for (s, e), rep in sorted(repls, key=lambda x: x[0][0], reverse=True):
        out = out[:s] + rep + out[e:]
    return out

# -------------------------
# Main scan logic (unit)
# -------------------------
def scan_unit(unit: Unit) -> dict:
    findings: List[Dict[str, Any]] = []
    replacements: List[Tuple[Tuple[int, int], str]] = []
    src = unit.code or ""

    # A) Handle ALL SELECT blocks (single or multiple tables)
    for m in SELECT_BLOCK_RE.finditer(src):
        full = m.group("full")
        start, end = m.span("full")

        # Check if the block mentions any obsolete table in FROM/JOIN positions
        contains_obsolete = False
        # Light check: look for any obsolete token; deeper check is done in remediate_select_block
        if LITERAL_TABLES_RE.search(full):
            # Attempt remediation
            new_block, changes = remediate_select_block(full)
            contains_obsolete = bool(changes)

            if contains_obsolete:
                msg = "SELECT uses obsolete FI/CO table(s) in FROM/JOIN."
                sev = "warning"
                # Build suggestion = full remediated block
                suggestion = new_block
                findings.append({
                    "pgm_name": unit.pgm_name,
                    "inc_name": unit.inc_name,
                    "type": unit.type,
                    "name": unit.name,
                    "class_implementation": unit.class_implementation,
                    "start_line": line_of_offset(src, start),
                    "end_line": line_of_offset(src, end),
                    "issue_type": "ObsoleteTableSelect",
                    "severity": sev,
                    "line": line_of_offset(src, start),
                    "message": msg,
                    "suggestion": suggestion,
                    "snippet": snippet_at(src, start, end),
                    "original_block": full,
                    "remediated_block": new_block,
                    "meta": {
                        "changes": changes
                    }
                })
                # Queue replacement for whole-file remediated_code
                replacements.append(((start, end), new_block))

    # B) UPDATE / DELETE / INSERT / MODIFY statements
    for stmt_type, pattern in [
        ("UPDATE", UPDATE_RE),
        ("DELETE", DELETE_RE),
        ("INSERT", INSERT_RE),
        ("MODIFY", MODIFY_RE),
    ]:
        for m in pattern.finditer(src):
            full = m.group("full").strip()
            start, end = m.span("full")

            new_stmt, changed_table = remediate_other_block(full, stmt_type)
            if changed_table:
                msg = f"{stmt_type} on obsolete table/view {changed_table}."
                sev = "error"  # write ops are not allowed on compatibility views
                findings.append({
                    "pgm_name": unit.pgm_name,
                    "inc_name": unit.inc_name,
                    "type": unit.type,
                    "name": unit.name,
                    "class_implementation": unit.class_implementation,
                    "start_line": line_of_offset(src, start),
                    "end_line": line_of_offset(src, end),
                    "issue_type": f"ObsoleteTable{stmt_type.title()}",
                    "severity": sev,
                    "line": line_of_offset(src, start),
                    "message": msg,
                    "suggestion": new_stmt,
                    "snippet": snippet_at(src, start, end),
                    "original_block": full,
                    "remediated_block": new_stmt,
                    "meta": {
                        "orig_table": changed_table,
                        "replacement_table": get_replacement_table(changed_table),
                        "context": "WRITE_OP"
                    }
                })
                replacements.append(((start, end), new_stmt))

    # C) Literal mentions (informational). Keep as-is; do not replace in code automatically.
    #    (We still emit a finding so callers can triage.)
    for m in LITERAL_TABLES_RE.finditer(src):
        table = m.group(1)
        t_up = table.upper()
        start, end = m.span(1)
        # Skip if this region is already covered by a SELECT/WRITE replacement
        covered = any(s <= start and end <= e for (s, e), _ in replacements)
        if covered:
            continue

        suggestion = f"Replace literal '{table}' with '{get_replacement_table(table)}' where applicable."
        findings.append({
            "pgm_name": unit.pgm_name,
            "inc_name": unit.inc_name,
            "type": unit.type,
            "name": unit.name,
            "class_implementation": unit.class_implementation,
            "start_line": line_of_offset(src, start),
            "end_line": line_of_offset(src, end),
            "issue_type": "ObsoleteTableLiteral",
            "severity": "info",
            "line": line_of_offset(src, start),
            "message": f"Obsolete table/view {t_up} used as a literal.",
            "suggestion": suggestion,
            "snippet": snippet_at(src, start, end),
            "original_block": table,
            "remediated_block": get_replacement_table(table),
            "meta": {
                "orig_table": t_up,
                "replacement_table": get_replacement_table(table),
                "context": "literal"
            }
        })

    res = unit.model_dump()
    res["findings"] = findings
    # Build whole-file remediated code
    res["remediated_code"] = apply_span_replacements(src, replacements) if replacements else src
    return res

def analyze_units(units: List[Unit]) -> List[Dict]:
    return [scan_unit(u) for u in units]

# -------------------------
# API
# -------------------------
@app.post("/remediate-array")
async def remediate_array(units: List[Unit]):
    """
    Returns, per unit:
      - findings[] with original_block and remediated_block for each issue
      - remediated_code (source with all SELECT/WRITE statements rewritten)
    """
    return analyze_units(units)

@app.get("/health")
def health():
    return {"ok": True}
