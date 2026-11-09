from __future__ import annotations
import argparse, csv, hashlib
from pathlib import Path
from .model import CASES, evaluate_case

def _write_results(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    rows = [evaluate_case(c) for c in CASES]
    fields = ["id","kind","pre","post","expected_pre","expected_post","ok","flips","description"]
    with (out/"cases.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields); w.writeheader()
        for r in rows: w.writerow({k:r[k] for k in fields})
    with (out/"summary.csv").open("w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["metric","value"])
        for m,v in [("cases",len(rows)),("ok",sum(1 for r in rows if r["ok"])),("pos",sum(1 for r in rows if r["kind"]=="pos")),("pos_flips",sum(1 for r in rows if r["kind"]=="pos" and r["flips"])),("neg",sum(1 for r in rows if r["kind"]=="neg")),("defense_in_depth",sum(1 for r in rows if r["kind"]=="did")),("adv",sum(1 for r in rows if r["kind"]=="adv")),("post_accept",sum(1 for r in rows if r["post"]=="ACCEPT"))]:
            w.writerow([m,v])
    with (out/"SHA256SUMS").open("w") as fh:
        for name in ("cases.csv","summary.csv"):
            fh.write(f"{hashlib.sha256((out/name).read_bytes()).hexdigest()}  {name}\n")

def main(argv=None) -> int:
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("case"); c.add_argument("id")
    r = sub.add_parser("results"); r.add_argument("dir")
    args = p.parse_args(argv)
    if args.cmd == "case":
        if args.id == "all":
            for case in CASES:
                row = evaluate_case(case)
                print(f"{row['id']}\tpre={row['pre']}\tpost={row['post']}\tok={row['ok']}\tflips={row['flips']}")
            return 0
        print(evaluate_case(next(c for c in CASES if c.id == args.id))); return 0
    _write_results(Path(args.dir)); return 0
if __name__ == "__main__":
    raise SystemExit(main())
