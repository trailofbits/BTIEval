import argparse
from tempfile import TemporaryDirectory
import subprocess
import os
import shutil


def apply_reduction(wdir, csmith_path, creduce_path, prop_shell_script, target_c_file, timeout_seconds, output_file):
    # TODO(Ian): we have some bug with paralellism here

    timed_out = False
    try:
        proc = subprocess.run([creduce_path, prop_shell_script, target_c_file], env={
            "CSMITH_PATH": csmith_path}, timeout=timeout_seconds, cwd=wdir)
    except subprocess.TimeoutExpired:
        timed_out = True

    if timed_out or proc.returncode == 0:
        shutil.copy(target_c_file, output_file)


def main():
    prsr = argparse.ArgumentParser("reduce a BTIEval test case")
    prsr.add_argument("--creduce_path", required=True,
                      help="path to creduce binary", default="creduce")
    prsr.add_argument("--csmith_path", required=True,
                      help="path to csmith root with bin and include dir")
    prsr.add_argument("--prop_shell_script", required=True,
                      help="path to interestingness test")
    prsr.add_argument("--timeout_secs", type=int, default=120)
    prsr.add_argument("target_cfile")

    args = prsr.parse_args()

    with TemporaryDirectory() as wdir:
        tfile_path = os.path.join(wdir, "test.c")
        out_dir = os.path.dirname(args.target_cfile)
        out_file = os.path.join(
            out_dir, os.path.basename(args.target_cfile)+"_reduced")
        shutil.copy(args.target_cfile, tfile_path)
        print(tfile_path)
        apply_reduction(wdir, os.path.realpath(args.csmith_path),
                        os.path.realpath(args.creduce_path),  os.path.realpath(
            args.prop_shell_script),  os.path.realpath(tfile_path), args.timeout_secs, os.path.realpath(out_file))


if __name__ == "__main__":
    main()
