#!/usr/bin/env python3
"""Fail-closed gate for the Argus Forge manifest.

Proves the claims made in manifest.yml comments, because a comment is not a
check (STANDARDS.md: every gate ships with a proof that it fails).

Checks:
  1. Zero Egress (Runs on Atlassian): no permissions.external, no top-level
     remotes/providers/endpoint/connectModules, no webtrigger module, no
     http(s) URL outside comments, and data residency storage (storage:app).
  2. Rovo pairing (TRAPS.md T2): rovo:agent key argus-incident-governor and
     rovo:mcp key argus-evidence-mcp-server exist, names <= 30 chars, and the
     agent action list equals the MCP tool list.
  2b. Rovo skill (TRAPS.md T2, second half): rovo:skill module points at a
     real skills/<name>/SKILL.md whose frontmatter obeys the Agent Skills
     spec as published by Atlassian (name matches directory, description
     50..1024 chars, allowed-tools covers dependencies.tools, body <= 500
     lines), the agent lists the skill, and the skill text is clean room.
  3. Wiring resolves: every action -> function, every function handler ->
     an export in src/<file>.js, every UI resource -> resources + disk path,
     every module key unique.
  4. Surfaces exist: site app has JSM/Jira panels, Confluence space
     page (with a route), and trigger, and declares no Compass module
     (Atlassian end-of-life rejection); the Bitbucket merge check + PR panel live in
     the companion apps/bitbucket/ app root because Forge rejects mixing
     Bitbucket workspace scopes with Jira site scopes.
  5. Write gate: escalate-standby-responder requires approvalDigest
     against a stored plan. Function keys stay within the Forge limit
     of 23 characters.
  6. Clean room: zero em dashes, zero banned words or names.
  7. app.id: reported USER-GATED when absent (never a silent pass), format
     checked when present. Atlassian assigns it via `forge register`.

Exit 0 = no FAIL (USER-GATED lines may still be printed), 1 = FAIL,
2 = PyYAML missing.

Requires PyYAML. In CI, install it explicitly; never on the dev machine C:
drive (local installs are banned on the maintainer machine).
"""
import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("FAIL: PyYAML is not installed; cannot prove anything. Exit 2.")
    sys.exit(2)

EXPECTED_AGENT_KEY = "argus-incident-governor"
EXPECTED_MCP_KEY = "argus-evidence-mcp-server"
EXPECTED_SKILL_KEY = "argus-socratic-canary-skill"
EXPECTED_SURFACES = {
    "jira:issuePanel",
    "jiraServiceManagement:queuePage",
    "confluence:spacePage",
    "trigger",
    "rovo:agent",
    "rovo:mcp",
    "rovo:skill",
    "action",
    "function",
}
COMPANION_SURFACES = {
    "bitbucket:mergeCheck",
    "bitbucket:repoPullRequestOverviewPanel",
    "function",
}
REQUIRED_SCOPES = {
    "storage:app",
    "read:servicedesk-request",
    "write:page:confluence",
}
COMPANION_REQUIRED_SCOPES = {
    "admin:repository:bitbucket",  # GET branch restrictions needs it
    "read:pullrequest:bitbucket",
    "read:repository:bitbucket",
}
FUNCTION_KEY_LIMIT = 23  # real Forge lint limit, run 41786704510
BANNED = [
    "compliant", "conformity",  # STANDARDS.md B4
    "hedno", "deddie", "reflective", "eurosos",  # employer/customer names never ship
    "cockroach", "backblaze", "qwen", "nebius", "xprize", "kaggle",  # G4
]

fails = []
gated = []


def fail(msg):
    fails.append(msg)
    print(f"FAIL: {msg}")


def ok(msg):
    print(f"PASS: {msg}")


def entries(modules, kind):
    value = modules.get(kind) or []
    return value if isinstance(value, list) else [value]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default="manifest.yml")
    ap.add_argument("--root", default=".")
    args = ap.parse_args()
    root = Path(args.root)
    mpath = Path(args.manifest)
    raw = mpath.read_text(encoding="utf-8")
    doc = yaml.safe_load(raw)
    if not isinstance(doc, dict):
        fail("manifest did not parse to a mapping")
        return finish()

    app = doc.get("app") or {}
    modules = doc.get("modules") or {}
    permissions = doc.get("permissions") or {}
    scopes = permissions.get("scopes") or []
    resources = doc.get("resources") or []

    # 1. Zero egress ---------------------------------------------------------
    if "external" in permissions:
        fail("permissions.external present: egress declared")
    for top in ("remotes", "providers", "endpoint", "connectModules"):
        if top in doc:
            fail(f"top-level {top}: present: Runs on Atlassian ineligible")
    if any("webtrigger" in k.lower() for k in modules):
        fail("webtrigger module present")
    code = "\n".join(l for l in raw.splitlines() if not l.lstrip().startswith("#"))
    if re.search(r"https?://", code):
        fail("http(s) URL outside a comment (possible self-hosted icon or egress)")
    if "storage:app" not in scopes:
        fail("storage:app missing: no data residency enabled storage")
    if not fails:
        ok("zero egress: no external/remotes/providers/endpoint/connectModules/"
           "webtrigger/URLs; storage:app present")

    # 2. Rovo pairing ---------------------------------------------------------
    agents = entries(modules, "rovo:agent")
    mcps = entries(modules, "rovo:mcp")
    actions = {a["key"]: a for a in entries(modules, "action")}
    agent = next((a for a in agents if a.get("key") == EXPECTED_AGENT_KEY), None)
    mcp = next((m for m in mcps if m.get("key") == EXPECTED_MCP_KEY), None)
    if agent is None:
        fail(f"rovo:agent key {EXPECTED_AGENT_KEY} missing")
    if mcp is None:
        fail(f"rovo:mcp key {EXPECTED_MCP_KEY} missing (TRAPS.md T2)")
    if len(mcps) > 1:
        fail("more than one rovo:mcp module (platform allows at most one)")
    if agent and len(agent.get("name", "")) > 30:
        fail("rovo:agent name over 30 characters")
    if mcp and len(mcp.get("name", "")) > 30:
        fail("rovo:mcp name over 30 characters")
    if agent and mcp:
        if set(agent.get("actions") or []) != set(mcp.get("tools") or []):
            fail("rovo:agent actions != rovo:mcp tools: pair has drifted")
        else:
            ok(f"rovo pair: agent actions == mcp tools "
               f"({len(mcp.get('tools') or [])} tools)")
        for key in mcp.get("tools") or []:
            if key not in actions:
                fail(f"mcp tool {key} has no action module")
            if len(key) >= 64:
                fail(f"action key {key} is 64+ characters (MCP limit)")

    # 2b. Rovo skill -------------------------------------------------------------
    skill_fails_before = len(fails)
    skills = entries(modules, "rovo:skill")
    skill = next((s for s in skills if s.get("key") == EXPECTED_SKILL_KEY), None)
    if skill is None:
        fail(f"rovo:skill key {EXPECTED_SKILL_KEY} missing (TRAPS.md T2)")
    if agent is not None and EXPECTED_SKILL_KEY not in (agent.get("skills") or []):
        fail("rovo:agent does not list the skill in its skills property")
    if skill is not None:
        dep_tools = (skill.get("dependencies") or {}).get("tools") or []
        if len(dep_tools) != len(set(dep_tools)):
            fail("rovo:skill dependencies.tools has duplicate keys")
        for key in dep_tools:
            if key not in actions:
                fail(f"rovo:skill tool {key} has no action module")
        rel_dir = (skill.get("source") or {}).get("dir", "")
        skill_dir = root / rel_dir
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.exists():
            fail(f"rovo:skill source.dir {rel_dir} has no SKILL.md on disk")
        else:
            skill_raw = skill_file.read_text(encoding="utf-8")
            parts = skill_raw.split("---", 2)
            if len(parts) < 3 or parts[0].strip():
                fail("SKILL.md does not start with a --- frontmatter block")
            else:
                front = yaml.safe_load(parts[1]) or {}
                name = front.get("name", "")
                if name != skill_dir.name:
                    fail(f"SKILL.md name {name!r} != directory name {skill_dir.name!r}")
                if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name or "") or len(name) > 64:
                    fail("SKILL.md name breaks the Agent Skills naming rule")
                description = front.get("description", "")
                if not (50 <= len(description) <= 1024):
                    fail(f"SKILL.md description is {len(description)} chars, need 50..1024")
                allowed = set((front.get("allowed-tools") or "").split())
                if not set(dep_tools) <= allowed:
                    fail("SKILL.md allowed-tools does not cover dependencies.tools")
                body_lines = parts[2].count("\n") + 1
                if body_lines > 500:
                    fail(f"SKILL.md body is {body_lines} lines, limit is 500")
            if "\u2014" in skill_raw:
                fail("em dash found in SKILL.md (STANDARDS.md F5)")
            for word in BANNED:
                if word in skill_raw.lower():
                    fail(f"banned string found in SKILL.md: {word}")
    if skill is not None and len(fails) == skill_fails_before:
        ok(f"rovo skill: {EXPECTED_SKILL_KEY} -> {rel_dir}/SKILL.md, "
           f"{len(dep_tools)} tool dependencies, frontmatter valid")

    # 3. Wiring resolves --------------------------------------------------------
    functions = {f["key"]: f for f in entries(modules, "function")}
    for key, action in actions.items():
        fn = action.get("function")
        if fn not in functions:
            fail(f"action {key} references missing function {fn}")
        if "endpoint" in action:
            fail(f"action {key} uses a remote endpoint: egress")
    for ref_kind, ref_entries in modules.items():
        for entry in entries(modules, ref_kind):
            if isinstance(entry, dict) and entry.get("function") and \
                    entry["function"] not in {f["key"] for f in entries(modules, "function")}:
                fail(f"{ref_kind} {entry.get('key')} references missing "
                     f"function {entry['function']}")
            callback = entry.get("callback") if isinstance(entry, dict) else None
            if isinstance(callback, dict) and callback.get("function") and \
                    callback["function"] not in {f["key"] for f in entries(modules, "function")}:
                fail(f"{ref_kind} {entry.get('key')} callback references "
                     f"missing function {callback['function']}")
    handler_exports = 0
    for key, fn in functions.items():
        if len(key) > FUNCTION_KEY_LIMIT:
            fail(f"function key {key} exceeds {FUNCTION_KEY_LIMIT} characters")
        handler = fn.get("handler", "")
        file_part, _, export = handler.partition(".")
        src_file = root / "src" / f"{file_part}.js"
        if not src_file.exists():
            fail(f"function {key}: handler file {src_file} does not exist")
            continue
        text = src_file.read_text(encoding="utf-8")
        if not re.search(rf"exports\.{re.escape(export)}\b", text):
            fail(f"function {key}: {src_file} does not export {export}")
        else:
            handler_exports += 1
    resource_keys = {r["key"]: r for r in resources}
    for kind in EXPECTED_SURFACES:
        for entry in entries(modules, kind):
            res = entry.get("resource")
            if res and res not in resource_keys:
                fail(f"{kind} {entry.get('key')} references missing resource {res}")
    for key, res in resource_keys.items():
        if not (root / res["path"]).exists():
            fail(f"resource {key}: path {res['path']} does not exist on disk")
    all_keys = []
    for kind, value in modules.items():
        for entry in entries(modules, kind):
            if isinstance(entry, dict) and entry.get("key"):
                all_keys.append(entry["key"])
    dupes = {k for k in all_keys if all_keys.count(k) > 1}
    if dupes:
        fail(f"duplicate module keys: {sorted(dupes)}")
    if not any("handler" in f or "resource" in f or "duplicate" in f for f in fails):
        ok(f"wiring: {len(actions)} actions, {len(functions)} functions, "
           f"{handler_exports} handler exports, {len(resource_keys)} resources, "
           f"{len(all_keys)} unique module keys")

    # 4. Surfaces ----------------------------------------------------------------
    missing = EXPECTED_SURFACES - set(modules)
    if missing:
        fail(f"missing module surfaces: {sorted(missing)}")
    else:
        ok(f"surfaces: all {len(EXPECTED_SURFACES)} site module types present "
           f"(JSM, Jira, Confluence, trigger, Rovo)")
    for panel in entries(modules, "jira:issuePanel"):
        if not panel.get("icon"):
            fail(f"jira:issuePanel {panel.get('key')} is missing the required icon")
        elif str(panel["icon"]).startswith(("http://", "https://")):
            fail(f"jira:issuePanel {panel.get('key')} icon is an external URL")
    compass_modules = sorted(k for k in modules if k.startswith("compass:"))
    if compass_modules:
        fail(f"Compass modules {compass_modules} cannot deploy in a new "
             f"Forge app (Compass end-of-life, CHANGE-3132)")
    for page in entries(modules, "confluence:spacePage"):
        if not page.get("route"):
            fail(f"confluence:spacePage {page.get('key')} is missing the required route")

    # 5. Scopes + write gate -------------------------------------------------
    if len(scopes) != len(set(scopes)):
        fail("duplicate scopes")
    bitbucket_scopes = sorted(s for s in scopes if s.endswith(":bitbucket"))
    if bitbucket_scopes:
        fail(f"site manifest declares Bitbucket workspace scopes "
             f"{bitbucket_scopes}: Forge rejects mixing them with site scopes")
    compass_scopes = sorted(s for s in scopes if s.endswith(":compass"))
    if compass_scopes:
        fail(f"site manifest declares Compass scopes {compass_scopes} "
             f"with no deployable Compass module")
    missing_scopes = REQUIRED_SCOPES - set(scopes)
    if missing_scopes:
        fail(f"missing required scopes: {sorted(missing_scopes)}")
    elif not bitbucket_scopes:
        ok(f"scopes: {len(scopes)} declared, required subset present, "
           f"zero Bitbucket workspace scopes")
    site_client = root / "src" / "adapters" / "forge_client.js"
    if site_client.exists() and "requestBitbucket" in site_client.read_text(encoding="utf-8"):
        fail("site forge_client.js calls requestBitbucket")
    escalate = actions.get("escalate-standby-responder") or {}
    escalate_inputs = escalate.get("inputs") or {}
    digest = escalate_inputs.get("approvalDigest") or {}
    if digest.get("required") is not True:
        fail("escalate-standby-responder does not require approvalDigest input")
    elif not {"changeId", "standbyAccountId", "elapsedSeconds"} <= set(escalate_inputs):
        fail("escalate-standby-responder is missing stored-plan execution inputs")
    else:
        ok("write gate: escalate-standby-responder requires approvalDigest "
           "and declares stored-plan execution inputs")
    if "open-verified-repair-pr" in actions:
        fail("site app still exposes open-verified-repair-pr: Bitbucket "
             "writes belong to the companion app")

    # 6. Clean room -------------------------------------------------------------
    if "\u2014" in raw:
        fail("em dash found in manifest (STANDARDS.md F5)")
    lowered = raw.lower()
    banned_hits = [word for word in BANNED if word in lowered]
    for word in banned_hits:
        fail(f"banned string found in manifest: {word}")
    if not banned_hits and "\u2014" not in raw:
        ok("clean room: 0 em dashes, 0 banned strings")

    # 7. app.id (user-gated, never a pass) --------------------------------------
    app_id = app.get("id")
    if not app_id:
        gated.append("app.id absent: run `forge register` after provisioning an "
                     "Atlassian Cloud Developer site (owner step). Not deployable yet.")
    elif not re.fullmatch(r"ari:cloud:ecosystem::app/[0-9a-f-]{36}", app_id):
        fail(f"app.id has the wrong shape: {app_id}")
    runtime = (app.get("runtime") or {}).get("name")
    if runtime != "nodejs24.x":
        fail(f"app.runtime.name is {runtime!r}, expected nodejs24.x (verified 2026-11-03)")

    # 8. Bitbucket companion manifest -----------------------------------------
    companion_path = root / "apps" / "bitbucket" / "manifest.yml"
    if mpath.name == "manifest.yml":
        check_companion(root, companion_path)

    return finish()


def check_companion(root, companion_path):
    if not companion_path.exists():
        fail("apps/bitbucket/manifest.yml missing: Bitbucket surfaces have no home")
        return
    craw = companion_path.read_text(encoding="utf-8")
    cdoc = yaml.safe_load(craw) or {}
    cmodules = cdoc.get("modules") or {}
    cpermissions = cdoc.get("permissions") or {}
    cscopes = cpermissions.get("scopes") or []
    if "external" in cpermissions or any(
            top in cdoc for top in ("remotes", "providers", "endpoint", "connectModules")):
        fail("companion manifest declares an egress surface")
    cmissing = COMPANION_SURFACES - set(cmodules)
    if cmissing:
        fail(f"companion manifest missing surfaces: {sorted(cmissing)}")
    merge = entries(cmodules, "bitbucket:mergeCheck")
    if merge and not ({"on-code-pushed", "on-merge"} <= set(merge[0].get("triggers") or [])):
        fail("companion merge check must trigger on-code-pushed and on-merge")
    site_scopes = sorted(s for s in cscopes
                           if not s.endswith(":bitbucket") and s != "storage:app")
    if site_scopes:
        fail(f"companion manifest declares site scopes {site_scopes}")
    write_scopes = sorted(s for s in cscopes if s.startswith("write:"))
    if write_scopes:
        fail(f"companion manifest declares write scopes {write_scopes}: "
             f"the deployed merge check is read-only")
    cmissing_scopes = COMPANION_REQUIRED_SCOPES - set(cscopes)
    if cmissing_scopes:
        fail(f"companion manifest missing scopes: {sorted(cmissing_scopes)}")
    cfunctions = {f["key"]: f for f in entries(cmodules, "function")}
    for key, fn in cfunctions.items():
        if len(key) > FUNCTION_KEY_LIMIT:
            fail(f"companion function key {key} exceeds {FUNCTION_KEY_LIMIT} characters")
        file_part, _, export = (fn.get("handler") or "").partition(".")
        src_file = companion_path.parent / "src" / f"{file_part}.js"
        if not src_file.exists() or not re.search(
                rf"exports\.{re.escape(export)}\b",
                src_file.read_text(encoding="utf-8")):
            fail(f"companion function {key}: handler {fn.get('handler')} does not resolve")
    for entry in merge:
        if entry.get("function") not in cfunctions:
            fail("companion merge check references a missing function")
    bb_client = companion_path.parent / "src" / "adapters" / "bitbucket_client.js"
    if not bb_client.exists():
        fail("companion bitbucket_client.js missing")
    else:
        bb_text = bb_client.read_text(encoding="utf-8")
        if "requestJira" in bb_text or "requestConfluence" in bb_text:
            fail("bitbucket_client.js calls a site product API")
    leaked = root / "src" / "adapters" / "bitbucket_client.js"
    if leaked.exists():
        fail("Bitbucket client is back under the site app src/ tree")
    if "\u2014" in craw or any(word in craw.lower() for word in BANNED):
        fail("companion manifest breaks the clean-room rule")
    capp_id = (cdoc.get("app") or {}).get("id")
    if not capp_id:
        gated.append("companion app.id absent: register the Bitbucket "
                     "companion app before it can deploy.")
    elif not re.fullmatch(r"ari:cloud:ecosystem::app/[0-9a-f-]{36}", capp_id):
        fail(f"companion app.id has the wrong shape: {capp_id}")
    ok(f"companion: {len(cfunctions)} functions, {len(cscopes)} workspace "
       f"scopes, merge check and PR panel wired")


def finish():
    for line in gated:
        print(f"USER-GATED: {line}")
    print(f"RESULT: {len(fails)} FAIL, {len(gated)} USER-GATED")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
