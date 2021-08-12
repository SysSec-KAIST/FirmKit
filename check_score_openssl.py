import os
import sys
import time
import yaml
import csv
import numpy as np

np.seterr(divide="ignore", invalid="ignore")

from optparse import OptionParser

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.append(os.path.abspath("./TikNib"))
from tiknib.utils import load_func_data, do_multiprocess
from tiknib.utils import flatten
from tiknib.utils import system

import logging
import coloredlogs
import pprint as pp

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


def get_base(image):
    return os.path.basename(image).replace(".tar.gz", "")


def scoring(x, alpha=1.0):
    # (image_path, bin_path, func_addr, func_name, arch)
    # :::(rdist, string, caller, callee, imported_callee, func_name) # depth-0
    # :::(rdist, string, caller, callee, imported_callee, func_name) # depth-1
    scores = x.split(":::")
    scores = list(map(lambda x: x.split(","), scores))
    image_path, bin_path, func_addr, func_name, arch = scores[0]
    final_score = 0
    for depth, score in enumerate(scores[1:]):
        score = list(map(float, score))
        rdist = score[0]
        str_score = score[1]
        caller_score = score[2]
        callee_score = score[3]
        imported_callee_score = score[4]
        func_name = score[5]

        if depth == 0:
            final_score += rdist * 1.0
            final_score += str_score * 1.0
            final_score += callee_score * 1.0
            final_score = final_score / 3
            break
    #            final_score += caller_score * 1.0
    #            final_score += func_name * 1.0
    #        elif depth == 1:
    #            final_score += caller_score * 1.0
    #            final_score += imported_callee_score * 1.0
    # final_score += func_name * 1.0

    # break # use depth-0

    return final_score


def check_vulnerable(target_func_name, version):
    if target_func_name == "ssl3_get_new_session_ticket":
        assert (
            "0.9.8" in version
            or "1.0.0" in version
            or "1.0.1" in version
            or "1.0.2" in version
        ), target_str

        return (
            "0.9.8" in version
            and version < "0.9.8zg"
            or "1.0.0" in version
            and version < "1.0.0s"
            or "1.0.1" in version
            and version < "1.0.1n"
            or "1.0.2" in version
            and version < "1.0.2b"
        )
    elif target_func_name == "tls1_process_heartbeat":
        assert (
            "0.9.8" in version
            or "1.0.0" in version
            or "1.0.1" in version
            or "1.0.2" in version
        ), target_str

        return "1.0.1" in version and version < "1.0.1g"
    else:
        raise


# TODO: handle force correctly
def check_helper(image, force=False):
    global g_outdir, g_config_fname, g_target_keys

    image_idx = get_base(image)
    outdir = g_outdir
    config_fname = g_config_fname
    target_keys = g_target_keys

    total_dir_name = os.path.join(outdir, config_fname, "scores_total")
    os.makedirs(total_dir_name, exist_ok=True)
    total_score_fname = os.path.join(total_dir_name, "scores_{}.txt".format(image_idx))

    if not force and os.path.exists(total_score_fname):
        with open(total_score_fname, "r") as f:
            lines = f.read().splitlines()

        for target_idx, target_key in enumerate(
            sorted(target_keys, key=lambda x: x[0])
        ):
            target_image_idx = target_key[0]
            target_bin_name = target_key[1]
            target_func_addr = hex(target_key[2])
            target_func_name = target_key[3]
            target_bin_arch = target_key[4]
            break
        lines.sort(key=lambda x: scoring(x), reverse=True)

    else:
        results = {}
        for target_idx, target_key in enumerate(
            sorted(target_keys, key=lambda x: x[0])
        ):
            target_image_idx = target_key[0]
            target_bin_name = target_key[1]
            target_func_addr = hex(target_key[2])
            target_func_name = target_key[3]
            target_bin_arch = target_key[4]

            dir_name = "_".join(
                [
                    "scores",
                    target_image_idx,
                    target_bin_name,
                    target_func_addr,
                    target_func_name,
                    target_bin_arch,
                ]
            )
            dir_name = os.path.join(outdir, config_fname, dir_name)

            score_fname = os.path.join(dir_name, "scores_{}.txt".format(image_idx))
            with open(score_fname, "r") as f:
                lines = f.read()

            lines = lines.splitlines()
            for idx, line in enumerate(lines):
                scores = line.split(":::")
                scores = list(map(lambda x: x.split(","), scores))
                image_path, bin_path, func_addr, func_name, arch = scores[0]
                bin_name = get_base(bin_path)

                func_key = (bin_path, func_addr, func_name)
                if func_key not in results:
                    results[func_key] = []

                float_scores = []
                for score in scores[1:]:
                    float_scores.append(list(map(float, score)))
                results[func_key].append(float_scores)

        out_str = ""
        for func_key in results.keys():
            total_score = np.mean(results[func_key], axis=0)
            out_str += "{},".format(image_idx)
            out_str += ",".join(func_key)
            out_str += ",all"
            for score in total_score:
                out_str += ":::{:.4f}".format(score[0])
                for val in score[1:]:
                    out_str += ",{:.4f}".format(val)
            out_str += "\n"
        lines = out_str.splitlines()
        lines.sort(key=lambda x: scoring(x), reverse=True)
        with open(total_score_fname, "w") as f:
            for line in lines:
                f.write(line + "\n")

    top_k = -1
    top_line = None
    top_score = 0
    prev_idx = 0
    prev_score = -1
    for idx, line in enumerate(lines):
        final_score = scoring(line)
        if final_score == prev_score:
            idx = prev_idx
        else:
            prev_idx = idx
            prev_score = final_score

        if target_func_name in line:
            top_k = idx + 1
            top_line = line
            top_score = final_score
            break

    return image_idx, top_k, top_line, top_score


def _init_check(outdir, config_fname, target_keys):
    global g_outdir, g_config_fname, g_target_keys
    g_outdir = outdir
    g_config_fname = config_fname
    g_target_keys = target_keys


def check(image_list, outdir, config_fname, ground_fname, debug):
    if not os.path.exists(config_fname):
        logger.error("No such config file: %s", config_fname)
        return

    t0 = time.time()
    logger.info("config file name: %s", config_fname)
    with open(config_fname, "r") as f:
        config = yaml.safe_load(f)

    with open(image_list, "r") as f:
        images = f.read().splitlines()

    if opts.debug:
        logger.warning("Debug mode, select only one image from %d.", len(images))
        # FOR DEBUG
        # images = list(filter(lambda x: "/2." in x, images))
        images = [images[0]]

    # for baseband
    if "modem.bin" in images[0]:
        images = list(map(lambda x: os.path.dirname(x), images))

    # Loading target functions
    result_suffix = config["result_suffix"]
    target_keys = []
    target_bins = set()
    for bin_path, funcs in config["target_funcs"].items():
        assert os.path.exists(bin_path), "No such file name: %s" % bin_path
        # TODO: fetch target function information *NOT* from a result or
        # feature file
        #
        #        if "_O0_" in bin_path or "_O1_" in bin_path:
        #            continue
        #
        bin_path, func_data_list = load_func_data(bin_path, suffix="_features")
        target_bins.add(bin_path)

        # image, bin, addr, name, arch
        target_data_list = list(filter(lambda x: x["startEA"] in funcs, func_data_list))

        image_base = get_base(os.path.dirname(bin_path))
        bin_base = get_base(bin_path)
        for func_data in target_data_list:
            func_key = (
                image_base,
                bin_base,
                func_data["startEA"],
                func_data["name"],
                func_data["arch"],
            )
            target_keys.append(func_key)
            target_func_name = func_data["name"]

    logger.info(
        "Loaded %d target functions in %d binaries.", len(target_keys), len(target_bins)
    )

    # Now check each score files
    logger.info("Start merging data ...")
    results = do_multiprocess(
        check_helper,
        images,
        chunk_size=1,
        threshold=1,
        initializer=_init_check,
        initargs=(outdir, config_fname, target_keys),
    )
    logger.info("Done. (%0.3fs)", time.time() - t0)

    total_ranks = list(filter(lambda x: x[1] != -1, results))
    total_ranks.sort(key=lambda x: x[-1], reverse=True)
    cnt = 0
    first_false_idx = None
    true_ranks = []
    false_ranks = []
    for score_idx, (image_idx, top_k, top_line, top_score) in enumerate(total_ranks):
        scores = top_line.split(":::")
        scores = list(map(lambda x: x.split(","), scores))
        image_path, bin_path, func_addr, func_name, arch = scores[0]
        full_bin_path = os.path.join(outdir, image_idx, bin_path.lstrip("/"))
        version_strs = system(
            'strings {} | grep "part of OpenSSL "'.format(full_bin_path)
        )
        if not version_strs:
            print("something wrong")
            import pdb

            pdb.set_trace()
        version_strs = version_strs.splitlines()
        target_str = version_strs[0]
        target_str = target_str.split()
        version = target_str[4]
        date = " ".join(target_str[-3:])
        if check_vulnerable(target_func_name, version):
            vulnerable = True
            cnt += 1
            true_ranks.append((score_idx, top_score))
        else:
            if not first_false_idx:
                first_false_idx = score_idx + 1
            vulnerable = False
            false_ranks.append((score_idx, top_score))
        print(
            score_idx,
            top_k,
            top_score,
            vulnerable,
            version,
            date,
            cnt,
            image_path,
            bin_path,
        )

    print("First false at rank: ", first_false_idx)
    print("Avg. rank, score of True: ", np.mean(true_ranks, axis=0))
    print("Avg. rank, score of False: ", np.mean(false_ranks, axis=0))

    # Plotting
    plt.style.use("seaborn-white")
    plt.rcParams["font.size"] = 40
    plt.rcParams["axes.labelsize"] = 40
    plt.rcParams["axes.titlesize"] = 40
    plt.rcParams["xtick.labelsize"] = 40
    plt.rcParams["ytick.labelsize"] = 40
    plt.rcParams["legend.fontsize"] = 30
    plt.rcParams["figure.titlesize"] = 40
    plt.rcParams["errorbar.capsize"] = 5

    fig = plt.figure(figsize=(20, 12))
    score_indices = list(map(lambda x: x[0] + 1, true_ranks))
    score_values = list(map(lambda x: x[1], true_ranks))
    plt.plot(
        score_indices,
        score_values,
        color="#ff0000",
        marker="o",
        markersize=14,
        linewidth=0,
        alpha=0.5,
        label="Vulnerable",
    )

    score_indices = list(map(lambda x: x[0] + 1, false_ranks))
    score_values = list(map(lambda x: x[1], false_ranks))
    plt.plot(
        score_indices,
        score_values,
        color="#0000ff",
        marker="^",
        markersize=14,
        linewidth=0,
        alpha=0.5,
        label="Patched",
    )

    plt.xlim([1, int(len(total_ranks) * 1.1)])
    plt.ylim([0.5, 1.0])
    plt.xlabel("Rank")
    plt.ylabel("Similarity Score")
    plt.legend(
        frameon=True, loc="upper right", fancybox=True, framealpha=0.8, borderpad=1
    )
    plt.tight_layout()

    plot_fname = os.path.join(outdir, config_fname + ".pdf")
    plt.savefig(plot_fname, format="pdf")
    plt.close(fig)

    # Printing average ranks
    if not total_ranks:
        ranks = np.nan
    else:
        ranks = list(map(lambda x: x[1], total_ranks))
    avg_rank = np.mean(ranks)
    print(
        "Target: ",
        func_data["name"],
        "\tRank: {:.2f} ({})".format(avg_rank, len(ranks)),
    )

    # Printing Top-k result
    for k in [1, 5, 10, 50, 100]:
        cnts = []
        for score_idx, (image_idx, top_k, top_line, top_score) in enumerate(
            total_ranks
        ):
            scores = top_line.split(":::")
            scores = list(map(lambda x: x.split(","), scores))
            image_path, bin_path, func_addr, func_name, arch = scores[0]
            full_bin_path = os.path.join(outdir, image_idx, bin_path.lstrip("/"))
            version_strs = system(
                'strings {} | grep "part of OpenSSL "'.format(full_bin_path)
            )
            version_strs = version_strs.splitlines()
            target_str = version_strs[0]
            target_str = target_str.split()
            version = target_str[4]
            date = " ".join(target_str[-3:])
            if check_vulnerable(target_func_name, version):
                vulnerable = True
                cnt += 1
            else:
                vulnerable = False

            if top_k <= k:
                cnts.append((top_line, top_score, vulnerable))

        cnt = len(cnts)
        true_cnt = len(list(filter(lambda x: x[-1], cnts)))
        print(
            "Top-{}: {} {:.2f}% {} {:.2f}%".format(
                k,
                cnt,
                float(cnt) / len(total_ranks) * 100,
                true_cnt,
                float(true_cnt) / len(total_ranks) * 100,
            )
        )
    logger.info("Done. (%0.3fs)", time.time() - t0)


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("--debug", action="store_true", dest="debug")
    op.add_option(
        "--image_list",
        action="store",
        type=str,
        dest="image_list",
        help="A file containing paths of firmware images. "
        "Each image should be 'tar.gz' format after running extractor.py",
    )
    op.add_option(
        "--outdir",
        action="store",
        type=str,
        dest="outdir",
        help="directory where output will be stored",
    )
    op.add_option(
        "--config",
        action="store",
        dest="config",
        help="give config file (ex) config_firmae_gcc.yml",
    )
    op.add_option(
        "--ground",
        action="store",
        dest="ground",
        help="give ground truth file (ex) ground_truth.txt",
    )
    (opts, args) = op.parse_args()
    if not opts.image_list or not os.path.exists(opts.image_list) or not opts.outdir:
        op.print_help()
        exit(1)

    file_handler = logging.FileHandler(os.path.join(opts.outdir, "check_log.txt"))
    logger.addHandler(file_handler)
    logger.info("output directory: %s", opts.outdir)

    check(opts.image_list, opts.outdir, opts.config, opts.ground, opts.debug)
