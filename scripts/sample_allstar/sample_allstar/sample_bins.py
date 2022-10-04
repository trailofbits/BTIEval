from sample_allstar.main import Binary, Package
import pickle
import argparse
from typing import List
import random
import tqdm

if __name__ == "__main__":
    prser = argparse.ArgumentParser("bin samp")
    prser.add_argument("target_bin_file", type=str)
    prser.add_argument("target_out_dir", type=str)
    prser.add_argument(
        "-n", type=int, help="number of binaries to grab", default=200)
    prser.add_argument("--fname_template", type=str, default="{name}.bin")
    args = prser.parse_args()

    with open(args.target_bin_file, "rb") as f:
        bins: List[Binary] = pickle.load(f)
        samp_bins = random.sample(bins, args.n)
        for b in tqdm.tqdm(samp_bins, total=len(samp_bins)):
            b.download_to_dir(args.target_out_dir, args.fname_template)
