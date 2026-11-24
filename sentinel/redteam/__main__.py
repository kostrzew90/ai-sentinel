import argparse
import sys

from sqlalchemy.orm import Session

from sentinel import config
from sentinel.db import engine
from sentinel.models import Base
from sentinel.redteam.runner import MODES, run, summary


def format_table(rows: list[dict]) -> str:
    header = ["scenario", "mode", "n", "success", "rate", "95% CI (Wilson)", "blocked", "refused", "invalid", "ok", "tried_forbidden", "false_block"]
    lines = [header]
    for r in rows:
        o = r["outcomes"]
        lines.append([
            r["scenario"], r["mode"], r["n"], r["k_success"], f"{r['rate']:.0%}",
            f"[{r['ci_low']:.1%}, {r['ci_high']:.1%}]", o["blocked"], o["refused"], o["invalid"], o["ok"],
            r["attempted_forbidden"], r["false_block"],
        ])
    widths = [max(len(str(line[i])) for line in lines) for i in range(len(header))]
    fmt = lambda line: " | ".join(str(c).ljust(w) for c, w in zip(line, widths))
    return "\n".join([fmt(lines[0]), "-+-".join("-" * w for w in widths), *map(fmt, lines[1:])])


def main() -> None:
    ap = argparse.ArgumentParser(prog="python -m sentinel.redteam")
    ap.add_argument("--provider", default=config.LLM_PROVIDER)
    ap.add_argument("--n", type=int, default=1)
    ap.add_argument("--modes", default=",".join(MODES))
    ap.add_argument("--scenarios", default="")
    ap.add_argument("--model-label", default=None)
    ap.add_argument("--fail-on-hardened-success", action="store_true", help="exit 1 if any hardened attempt has outcome success")
    args = ap.parse_args()
    modes = [m for m in args.modes.split(",") if m]
    bad = set(modes) - set(MODES)
    if bad:
        ap.error(f"unknown modes: {sorted(bad)}")
    Base.metadata.create_all(engine)
    run_id = run(
        args.provider, args.n, modes, [s for s in args.scenarios.split(",") if s] or None,
        args.model_label, progress=lambda m: print(m, file=sys.stderr, flush=True),
    )
    with Session(engine) as s:
        rows = summary(s, run_id)
    print(format_table(rows))
    if args.fail_on_hardened_success:
        bad = [r for r in rows if r["mode"] == "hardened" and r["k_success"]]
        if bad:
            print(f"FAIL: successful attack in hardened mode: {[r['scenario'] for r in bad]}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
