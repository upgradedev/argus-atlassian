#!/usr/bin/env python3
"""Fail-closed gate for the Argus Forge manifest.

Proves the claims made in manifest.yml comments, because a comment is not a
check (every gate ships with a proof that it fails).

Checks:
  1. Zero Egress (Runs on Atlassian): no permissions.external, no top-level
     remotes/providers/endpoint/connectModules, no webtrigger module, no
     http(s) URL outside comments, and data residency storage (storage:app).
  2. Rovo pairing: rovo:agent key argus-incident-governor and
     rovo:mcp key argus-evidence-mcp-server exist, names <= 30 chars, and the
     agent action list equals the MCP tool list.
  2b. Rovo skill: rovo:skill module points at a
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

Requires PyYAML.
"""
import argparse
import hashlib
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
# SHA-256 digests of banned clean-room tokens (stored hashed so no banned
# vocabulary or internal workspace filename is shipped in plaintext).
BANNED_TOKEN_SHA256 = {
    "b67c263c0379939b5a3389c0624c2837d133007be5914b49aaa4afacb6f146b6",
    "a78ef0a05a15ff15828d17cca6c6e985b64a5f8fd54cc905870bb4f767c6556c",
    "55206b0fd456c2179beb58ff8c4e7b85de9abda70c4098759ae63664c8f97fa1",
    "766a82aaaf484c93da6a8954357522e19a6e2be3c2264f00bbf456761840d461",
    "9a0d9562322f17bf7ce5c9100db2f46a27b719fa016783de08262ae68af5c8e3",
    "dce263216c6e5f6f9266a952b2d6ebf83bcfe4eb90b6857d46820fcc7c5f23e2",
    "16fd3c9b3a28501f74ccd4742a24da9885a257f2d4fffc27bb07dc49c099ba43",
    "7a03c4bbd666dfa8aa5b86a15333b50a0c8755e5e499e0e75532ee7277a29a60",
    "67f2d22514622d1be30c14ee9f3cb104503a159a33a656ca91a1953aa9616429",
    "59719e65a648bd4677d233821f3e56b1035cc74f11420a21820b4064c2b7ffd9",
    "1fce355b00c34ccbfdfe9c93f8c601a4259256e690541f0ef3e315912d0ef79b",
    "e839e162d8106fe35160d44676559cc5b7cd62284058792011d52976e8a2a0e1",
    "b951327c37d8a1ed4d5ed18908681f6aca718ecdfe174aa39cf2237547f92fe7",
    "3b1445640016e175ac4726662ebe4a8674f04966d3885c788cd459e7874deb26",
    "e274b356a5c400b8b627696c57ce215277a9f7864b8ea762bfe4bb118fffe308",
    "b4b88b130f00da91f244fc1fdeb08190ac16fe503e70cb3eab37d13a0dcfacbb",
    "bccc86317c281a19e56f3f941077ea61b3fb37d5bd527c518b92b188c4461251",
    "38f7cf0b4ff37a008fbb79d2f153f9b854944b52fa50c97c0d4b0edc47426bc3",
    "bec1b4f06305c3593120938be464c010eeab0396d2479ee5b7aca27e0f4ca618",
    "c637d92d2bb72ae06c9f2eaaad6e992484914d6f2acf7b902281a399c37e931c",
}


def find_banned_tokens(text):
    lowered = text.lower()
    candidates = set(re.findall(r"[a-z0-9]+", lowered)) | set(
        re.findall(r"[a-z0-9]+(?:[-.][a-z0-9]+)+", lowered)
    )
    hits = []
    for token in sorted(candidates):
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if digest in BANNED_TOKEN_SHA256:
            hits.append(token)
    return hits


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
        fail(f"rovo:mcp key {EXPECTED_MCP_KEY} missing")
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
        fail(f"rovo:skill key {EXPECTED_SKILL_KEY} missing")
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
                fail("em dash found in SKILL.md")
            for word in find_banned_tokens(skill_raw):
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
        fail("em dash found in manifest")
    banned_hits = find_banned_tokens(raw)
    for word in banned_hits:
        fail(f"banned string found in manifest: {word}")
    repo_clean = True
    if mpath.name == "manifest.yml":
        for sub in ("src", "tests", "scripts", "skills", ".github", "apps"):
            base = root / sub
            if not base.exists():
                continue
            for fpath in sorted(base.rglob("*")):
                if not fpath.is_file() or fpath.suffix in {".png", ".jpg", ".ico", ".woff2"}:
                    continue
                ftext = fpath.read_text(encoding="utf-8", errors="replace")
                fhits = find_banned_tokens(ftext)
                if fhits:
                    repo_clean = False
                    fail(f"banned string found in {fpath.relative_to(root)}: {fhits[0]}")
        for top_file in (".gitignore", "README.md"):
            tpath = root / top_file
            if tpath.exists():
                thits = find_banned_tokens(tpath.read_text(encoding="utf-8", errors="replace"))
                if thits:
                    repo_clean = False
                    fail(f"banned string found in {top_file}: {thits[0]}")
    if not banned_hits and "\u2014" not in raw and repo_clean:
        ok("clean room: 0 em dashes, 0 banned strings across manifests and repo")

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
    if "\u2014" in craw or find_banned_tokens(craw):
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
