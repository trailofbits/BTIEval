from multiprocessing.util import log_to_stderr
import subprocess
import argparse
import tempfile
import os
import tqdm
import shutil


class TestCase:
    def __init__(self, csmith_path: str,  prop_shell_script: str, tc_id: int, save_dir: str) -> None:
        self.wdir = None
        self.tmpdir = tempfile.TemporaryDirectory()
        self.csmith_path = csmith_path
        self.fname = "test.c"
        self.prop_shell_script = prop_shell_script
        self.save_dir = save_dir
        self.tc_id = tc_id
        self.log_stderr = os.path.join(
            self.save_dir, f"log_{tc_id}.stderr") if self.save_dir else None
        self.log_stdout = os.path.join(
            self.save_dir, f"log_{tc_id}.stdout") if self.save_dir else None

    def __enter__(self):
        self.wdir = self.tmpdir.__enter__()
        return self

    def __exit__(self, exc, value, tb):
        self.tmpdir.__exit__(exc, value, tb)

    def run_command(self, args):
        lstderr_name = self.log_to_stderr if self.log_stderr else "/dev/null"
        lstdout_name = self.log_stdout if self.log_stdout else "/dev/null"
        with open(lstderr_name, "a+") as lstderr:
            with open(lstdout_name, "a+") as lstdout:
                proc = subprocess.Popen(args, cwd=self.wdir, env={
                                        "CSMITH_PATH": self.csmith_path}, stdout=lstdout, stderr=lstderr)
                proc.wait()
                return proc.returncode == 0

    def run_command_expect_success(self, args):
        if not self.run_command(args):
            raise RuntimeError("command failed: {args}")

    def generate_c(self):
        self.run_command_expect_success(
            [os.path.join(self.csmith_path, "src", "csmith"), "-o", self.fname])

    def has_prop(self):
        return self.run_command([self.prop_shell_script])

    def save_curr_c_to(self, fstring: str):
        if self.save_dir:
            to_write_to = os.path.join(
                self.save_dir, fstring.format(self.tc_id))
            shutil.copy(os.path.join(self.wdir, self.fname),
                        to_write_to)


def run_test_case(tc: TestCase):
    with tc:
        tc.generate_c()
        if not tc.has_prop():
            return False
        else:
            tc.save_curr_c_to("initial_tc_{}.c")
            return True


def main():
    prser = argparse.ArgumentParser("csmith tester for BTIGhidra")
    prser.add_argument("--csmith_path", required=True,
                       help="path to csmith root with bin and include dir")
    prser.add_argument("--prop_shell_script", required=True,
                       help="path to interestingness test")
    prser.add_argument("--save_test_cases", type=str)
    prser.add_argument("--num_test_cases", default=200, type=int)
    prser.add_argument("--ci", action="store_true",
                       help="in ci mode the script exits on failure with an error code")

    args = prser.parse_args()

    tcs = [TestCase(os.path.realpath(args.csmith_path), os.path.realpath(args.prop_shell_script), i,  os.path.realpath(args.save_test_cases) if args.save_test_cases else None)
           for i in range(0, args.num_test_cases)]

    for tc in tqdm.tqdm(tcs, total=len(tcs)):
        if run_test_case(tc):
            print("tc failed")
            exit(1)
    exit(0)


if __name__ == "__main__":
    main()
