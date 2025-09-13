from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Any, Dict, Tuple
import re

app = FastAPI(
    title="ABAP DB Operation Remediator for S/4HANA Obsolete FI/CO Tables (Note 2431747) — full-file + snippets"
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
# Regexes
# -------------------------
# Safer FROM/JOIN table capture: only capture an alias if the token is NOT a keyword like INTO/WHERE/JOIN/etc.
RESERVED_FOLLOWERS = r"(?:INTO|WHERE|INNER|LEFT|RIGHT|FULL|CROSS|JOIN|ORDER|GROUP|HAVING|FOR|ON|BY|UNION|UP|WITH)\b"

FROM_TBL_RE = re.compile(
    rf"""\bFROM\s+
        (?P<table>\w+)
        (?P<after>
            \s+(?:AS\s+)?       # optional 'AS '
            (?!{RESERVED_FOLLOWERS})
            (?P<alias>\w+)      # alias token (only if not a reserved word)
        )?
    """,
    re.IGNORECASE | re.VERBOSE,
)

JOIN_TBL_RE = re.compile(
    rf"""\bJOIN\s+
        (?P<table>\w+)
        (?P<after>
            \s+(?:AS\s+)?       # optional 'AS '
            (?!{RESERVED_FOLLOWERS})
            (?P<alias>\w+)      # alias token (only if not a reserved word)
        )?
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Match any full SELECT statement up to a period.
SELECT_BLOCK_RE = re.compile(r"(?P<full>SELECT[\s\S]*?\.)", re.IGNORECASE)

# Other DML
UPDATE_RE = re.compile(r"(UPDATE\s+\w+[\s\S]*?\.)", re.IGNORECASE)
DELETE_RE = re.compile(r"(DELETE\s+FROM\s+\w+[\s\S]*?\.)", re.IGNORECASE)
INSERT_RE = re.compile(r"(INSERT\s+\w+[\s\S]*?\.)", re.IGNORECASE)
MODIFY_RE = re.compile(r"(MODIFY\s+\w+[\s\S]*?\.)", re.IGNORECASE)

# Literal obsolete table names anywhere
LITERAL_TABLES_RE = re.compile(
    r"\b(" + "|".join(re.escape(t) for t in OBSOLETE_TABLES) + r")\b",
    re.IGNORECASE
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
    suggestion: Optional[str] = None   # remediated snippet
    snippet: Optional[str] = None      # original full statement
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
# Helpers
# -------------------------
def line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1

def get_replacement_table(table: str) -> str:
    t_up = (table or "").upper()
    if t_up in NO_VIEW_TABLES:
        return "ACDOCA"
    elif t_up in TABLE_MAPPING:
        return TABLE_MAPPING[t_up]["source"].split("/")[0]
    return table

def remediation_comment(table: str, stmt_type: str) -> str:
    t_up = (table or "").upper()
    if stmt_type in ("UPDATE", "INSERT", "MODIFY", "DELETE"):
        return "/* NOTE: Compatibility view cannot be used for write operations in S/4HANA. Use ACDOCA or source table directly. */"
    if t_up in NO_VIEW_TABLES:
        return f"/* NOTE: {t_up} is obsolete in S/4HANA. Use ACDOCA directly and map fields accordingly. */"
    elif t_up in TABLE_MAPPING:
        src = TABLE_MAPPING[t_up]["source"]
        return f"/* NOTE: {t_up} is obsolete in S/4HANA. Adapt to ACDOCA or compatibility view (source: {src}). */"
    return ""

def inject_inline_comment(after_table_token: str, table: str, stmt_type: str) -> str:
    """
    Put the note right after the table(+alias) token, before any next keyword.
    """
    comment = remediation_comment(table, stmt_type)
    return after_table_token + (f" {comment}" if comment else "")

def replace_from_join_tables(block: str, stmt_type: str) -> Tuple[str, List[Dict[str, str]]]:
    """
    Replace obsolete tables in FROM/JOIN within the given SELECT block.
    Preserve alias and position comments safely after the table/alias token.
    """
    changes: List[Dict[str, str]] = []

    def _repl_func(m: re.Match, kw: str) -> str:
        table = m.group("table")
        after = m.group("after") or ""
        t_up = (table or "").upper()
        if t_up in OBSOLETE_TABLES:
            repl_tbl = get_replacement_table(table)
            token = f"{repl_tbl}{after}"
            token = inject_inline_comment(token, table, "SELECT")
            changes.append({"orig": t_up, "repl": repl_tbl, "context": kw})
            return f"{kw} {token}"
        return m.group(0)

    # Replace first FROM occurrence
    out = FROM_TBL_RE.sub(lambda mm: _repl_func(mm, "FROM"), block, count=1)
    # Replace all JOIN occurrences
    out = JOIN_TBL_RE.sub(lambda mm: _repl_func(mm, "JOIN"), out)
    return out, changes

def remediate_select_block(block: str) -> Tuple[str, bool, List[Dict[str, str]]]:
    """
    Returns (new_block, changed?, changes_list)
    """
    contains_obsolete = bool(LITERAL_TABLES_RE.search(block))
    if not contains_obsolete:
        return block, False, []
    new_block, changes = replace_from_join_tables(block, "SELECT")
    changed = (new_block != block)
    return new_block, changed, changes

def remediate_other_stmt(stmt: str, stmt_type: str) -> Tuple[str, bool, Dict[str, str]]:
    """
    For UPDATE/DELETE/INSERT/MODIFY statements, replace the target table if obsolete.
    """
    # Get the table token
    if stmt_type == "DELETE":
        table_match = re.search(r"DELETE\s+FROM\s+(\w+)", stmt, re.IGNORECASE)
    elif stmt_type == "SELECT":
        table_match = re.search(r"FROM\s+(\w+)", stmt, re.IGNORECASE)
    else:
        table_match = re.search(rf"{stmt_type}\s+(\w+)", stmt, re.IGNORECASE)
    if not table_match:
        return stmt, False, {}

    table = table_match.group(1)
    t_up = table.upper()
    if t_up not in OBSOLETE_TABLES:
        return stmt, False, {}

    repl = get_replacement_table(table)
    note = remediation_comment(table, stmt_type)
    if stmt_type in ("DELETE", "SELECT"):
        new_stmt = re.sub(rf"({stmt_type}\s+FROM\s+){re.escape(table)}\b",
                          rf"\1{repl}" + (f" {note}" if note else ""),
                          stmt, flags=re.IGNORECASE)
    else:
        new_stmt = re.sub(rf"({stmt_type}\s+){re.escape(table)}\b",
                          rf"\1{repl}" + (f" {note}" if note else ""),
                          stmt, flags=re.IGNORECASE)
    return new_stmt, (new_stmt != stmt), {"orig": t_up, "repl": repl, "context": stmt_type}

def apply_span_replacements(source: str, repls: List[Tuple[Tuple[int, int], str]]) -> str:
    """
    Apply multiple (start,end)->replacement edits safely (right-to-left).
    """
    out = source
    for (s, e), r in sorted(repls, key=lambda x: x[0][0], reverse=True):
        out = out[:s] + r + out[e:]
    return out

def pack_issue(unit: Unit, issue_type: str, message: str, severity: str,
               start: int, end: int, suggestion: str, snippet: str, meta: dict = None) -> Dict[str, Any]:
    src = unit.code or ""
    return {
        "pgm_name": unit.pgm_name,
        "inc_name": unit.inc_name,
        "type": unit.type,
        "name": unit.name,
        "class_implementation": unit.class_implementation,
        "start_line": unit.start_line,
        "end_line": unit.end_line,
        "issue_type": issue_type,
        "severity": severity,
        "line": line_of_offset(src, start),
        "message": message,
        "suggestion": suggestion,  # remediated snippet
        "snippet": snippet,        # full original statement
        "meta": meta or {}
    }

# -------------------------
# Main scan logic (single unit)
# -------------------------
def scan_unit(unit: Unit) -> dict:
    findings: List[Dict[str, Any]] = []
    src = unit.code or ""
    repls: List[Tuple[Tuple[int, int], str]] = []

    # 1) Full SELECT statements
    for m in SELECT_BLOCK_RE.finditer(src):
        full_stmt = m.group("full")
        new_stmt, changed, changes = remediate_select_block(full_stmt)
        if changed:
            # Suggestion: remediated snippet; Snippet: full original statement
            msg = "SELECT uses obsolete FI/CO table(s) — redirected to ACDOCA/compatibility view."
            sev = "warning"
            meta = {"changes": changes}
            findings.append(
                pack_issue(unit, "ObsoleteTableSelect", msg, sev, m.start(), m.end(), new_stmt, full_stmt, meta)
            )
            repls.append(((m.start(), m.end()), new_stmt))

    # 2) UPDATE/DELETE/INSERT/MODIFY single statements
    for stmt_type, pattern in [
        ("UPDATE", UPDATE_RE),
        ("DELETE", DELETE_RE),
        ("INSERT", INSERT_RE),
        ("MODIFY", MODIFY_RE),
    ]:
        for mx in pattern.finditer(src):
            stmt_text = mx.group(1)
            new_stmt, changed, change_meta = remediate_other_stmt(stmt_text, stmt_type)
            if changed:
                msg = f"{stmt_type} uses obsolete FI/CO table — not allowed on compatibility views; adjust to ACDOCA."
                sev = "error"  # writes are critical
                findings.append(
                    pack_issue(unit, f"ObsoleteTable{stmt_type.title()}", msg, sev, mx.start(1), mx.end(1), new_stmt, stmt_text, change_meta)
                )
                repls.append(((mx.start(1), mx.end(1)), new_stmt))

    # 3) Literal table mentions anywhere (info)
    # (We report but do not auto-replace these, since context could be non-SQL.)
    for ml in LITERAL_TABLES_RE.finditer(src):
        table = ml.group(1)
        t_up = table.upper()
        # If this literal lies inside an already-replaced span, skip double reporting
        findings.append(
            pack_issue(
                unit,
                "ObsoleteTableLiteral",
                f"Obsolete table/view {t_up} used as a literal.",
                "info",
                ml.start(),
                ml.end(),
                f"Replace literal '{table}' with '{get_replacement_table(table)}' where applicable.",
                src[max(0, ml.start()-60):min(len(src), ml.end()+60)]
            )
        )

    remediated_code = apply_span_replacements(src, repls)

    res = unit.model_dump()
    res["original_code"] = src
    res["remediated_code"] = remediated_code
    res["findings"] = findings
    return res

def analyze_units(units: List[Unit]) -> List[Dict[str, Any]]:
    return [scan_unit(u) for u in units]

# -------------------------
# API
# -------------------------
@app.post("/remediate-array")
async def remediate_array(units: List[Unit]):
    return analyze_units(units)

@app.get("/health")
def health():
    return {"ok": True}
