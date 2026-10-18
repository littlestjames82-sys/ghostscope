"""GhostScope CLI.

Commands:
  pack     build a review pack from --base/--head, --staged, or --diff
  explain  why a file is (or is not) in a pack, its mode and reasons
  check    validate a pack against its manifest
  mcp      run the stdio MCP server (scope_pack, scope_explain)

Local git only. No hosting API, no model calls, no network.
Exit codes: 0 ok, 1 fit budget not met (pack still written) or
check failed, 2 usage/input errors.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .gitinput import ScopeInputError, load_change_input
from .pack import build_pack, explain_from_scope
from .profile import load_scope_profile


def _add_input_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base", help="base git ref (default HEAD~1)")
    parser.add_argument("--head", help="head git ref (default HEAD)")
    parser.add_argument("--staged", action="store_true",
                        help="use staged changes (git diff --cached)")
    parser.add_argument("--diff", dest="diff_file",
                        help="path to a unified diff file")
    parser.add_argument("--no-verify-diff", action="store_true",
                        help="skip the diff-vs-content verification")


def _load_input(args, project):
    return load_change_input(
        project, base=getattr(args, "base", None),
        head=getattr(args, "head", None),
        staged=getattr(args, "staged", False),
        diff_file=getattr(args, "diff_file", None),
        verify=not getattr(args, "no_verify_diff", False))


def cmd_pack(args) -> int:
    try:
        profile = load_scope_profile(args.project)
        inp = _load_input(args, args.project)
        result = build_pack(args.project, args.out, inp, profile, fit=args.fit)
    except (ScopeInputError, ValueError, FileNotFoundError) as exc:
        print(f"ghostscope: {exc}", file=sys.stderr)
        return 2
    scope = result["scope"]
    totals = scope["totals"]
    if args.json:
        print(json.dumps({"out": result["out"], "totals": totals,
                          "changed": scope["changed"],
                          "reading_order": scope["reading_order"],
                          "notes": scope["notes"],
                          "fit": scope["fit"],
                          "fit_ok": result["fit_ok"]}, indent=2))
    else:
        print(f"Pack written to {result['out']}")
        print(f"Changed files: {totals['changed_files']}; pack files: "
              f"{totals['pack_files']}")
        print(f"Estimated tokens: repo {totals['repo_tokens_estimate']}, "
              f"diff {totals['diff_tokens_estimate']}, "
              f"pack {totals['pack_tokens_estimate']} (estimates)")
        for item in scope["reading_order"]:
            reasons = "; ".join(item["risk_reasons"])
            print(f"  {item['order']}. {item['path']} [{item['mode']}]"
                  f" risk {item['risk_score']}"
                  f"{' - ' + reasons if reasons else ''}")
        if scope["fit"] and not scope["fit"]["ok"]:
            print(f"Fit budget {scope['fit']['requested_tokens']} NOT met "
                  f"(pack needs {scope['fit']['after_tokens']}); changed "
                  "files are never downgraded.")
    return 0 if result["fit_ok"] else 1


def cmd_explain(args) -> int:
    path = args.file
    if args.pack_dir:
        try:
            scope = json.loads(
                (Path(args.pack_dir) / "scope.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"ghostscope: cannot read pack: {exc}", file=sys.stderr)
            return 2
        result = explain_from_scope(scope, path)
    else:
        try:
            profile = load_scope_profile(args.project)
            inp = _load_input(args, args.project)
            from .pack import _mode_for, analyse
            analysis = analyse(args.project, inp, profile)
            entries = analysis["scan"].by_path()
            mode = _mode_for(path, {**analysis,
                                    "covering_tests_all": analysis["covering_tests_all"]},
                             entries) if path in entries else None
            rep = next((c for c in analysis["changed"] if c["path"] == path), None)
            result = {
                "path": path, "in_pack": mode is not None, "mode": mode,
                "distance": analysis["distances"].get(path),
                "risk_score": rep["risk_score"] if rep else None,
                "risk_reasons": rep["risk_reasons"] if rep else [],
                "covering_test": path in analysis["covering_tests_all"],
            }
            if mode is None:
                result["reason"] = ("not a changed file, not a covering test, "
                                    "and not within graph distance 2 of a "
                                    "changed file")
        except (ScopeInputError, ValueError, FileNotFoundError) as exc:
            print(f"ghostscope: {exc}", file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["in_pack"]:
            print(f"{path}: in pack, mode {result['mode']}, "
                  f"distance {result.get('distance')}, "
                  f"risk score {result.get('risk_score')}")
            for r in result.get("risk_reasons", []):
                print(f"  - {r}")
        else:
            print(f"{path}: not in pack - {result.get('reason', '')}")
    return 0


def cmd_check(args) -> int:
    from .validate import validate_pack
    result = validate_pack(args.bundle)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["ok"]:
            print(f"OK: {result['files_checked']} files checked, "
                  f"{result['total_sliced_tokens']} sliced tokens (estimates)")
        else:
            print("INVALID pack:")
            for e in result["errors"]:
                print(f"  - {e}")
    return 0 if result["ok"] else 1


def cmd_mcp(args) -> int:
    from .mcp_server import serve
    return serve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghostscope",
        description="PR and diff review slicer for GhostSlice (local only)")
    parser.add_argument("--version", action="version",
                        version=f"ghostscope {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("pack", help="build a review pack")
    p.add_argument("project")
    p.add_argument("-o", "--out", required=True, help="output pack directory")
    _add_input_args(p)
    p.add_argument("--fit", type=int,
                   help="token budget (estimates); changed files never downgraded")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_pack)

    p = sub.add_parser("explain", help="explain a file's place in a pack")
    p.add_argument("project")
    p.add_argument("file")
    p.add_argument("--pack", dest="pack_dir",
                   help="existing pack directory (reads its scope.json)")
    _add_input_args(p)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_explain)

    p = sub.add_parser("check", help="validate a pack against its manifest")
    p.add_argument("bundle")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("mcp", help="run the stdio MCP server")
    p.set_defaults(fn=cmd_mcp)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
