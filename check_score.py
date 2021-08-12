import os
import sys
import time
import yaml
import csv
import numpy as np

np.seterr(divide="ignore", invalid="ignore")

from optparse import OptionParser

sys.path.append(os.path.abspath("./TikNib"))
from tiknib.utils import load_func_data, do_multiprocess
from tiknib.utils import flatten

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
            final_score /= 3
    #            final_score += caller_score * 1.0
    #            final_score += func_name * 1.0
    #        elif depth == 1:
    #            final_score += caller_score * 1.0
    #            final_score += imported_callee_score * 1.0
    # final_score += func_name * 1.0

    # break # use depth-0

    return final_score


def check_helper(image):
    global g_outdir, g_firmware_info, g_ground
    # g_ground is ground truth information for current target function

    image_idx = get_base(image)
    device_name, device_vendor, device_arch = g_firmware_info[image_idx]

    if image_idx in g_ground:
        target_name, target_addr = g_ground[image_idx]
        ground = True
    else:
        target_name = ""
        target_addr = ""
        ground = False

    score_fname = os.path.join(g_outdir, "scores_{}.txt".format(image_idx))
    with open(score_fname, "r") as f:
        lines = f.read().splitlines()

    # TODO: implement scoring
    lines.sort(key=lambda x: scoring(x), reverse=True)
    results = []

    top_k = -1
    prev_idx = 0
    prev_score = -1
    for idx, line in enumerate(lines):
        final_score = scoring(line)
        if final_score == prev_score:
            idx = prev_idx
        else:
            prev_idx = idx
            prev_score = final_score

        scores = line.split(":::")
        scores = list(map(lambda x: x.split(","), scores))
        image_path, bin_path, func_addr, func_name, arch = scores[0]
        bin_name = get_base(bin_path)
        bin_path = bin_path.replace("output/{}".format(image_idx), "")
        results.append(
            (
                image_idx,
                "{:.4f}".format(final_score),
                ground,
                func_addr,
                func_name,
                bin_path,
                arch,
                device_vendor,
                device_name,
            )
        )
        if not target_name or bin_name == target_name:
            if not target_addr or func_addr == target_addr:
                top_k = idx + 1
                break  # TODO: implement merged result

    return image_idx, top_k, results


def _init_check(outdir, firmware_info, ground):
    global g_outdir, g_firmware_info, g_ground
    g_outdir = outdir
    g_firmware_info = firmware_info
    g_ground = ground


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
    if "modem_unpacked.bin" in images[0]:
        images = list(map(lambda x: os.path.dirname(x), images))

    # Loading target functions
    result_suffix = config["result_suffix"]
    target_keys = []
    target_bins = set()
    for bin_path, funcs in config["target_funcs"].items():
        assert os.path.exists(bin_path), "No such file name: %s" % bin_path
        # TODO: fetch target function information *NOT* from a result file
        bin_path, func_data_list = load_func_data(bin_path, suffix=result_suffix)
        target_bins.add(bin_path)

        # image, bin, addr, name, arch
        target_data_list = list(filter(lambda x: x[2] in funcs, func_data_list))

        image_base = get_base(os.path.dirname(bin_path))
        bin_base = get_base(bin_path)
        for func_data in target_data_list:
            func_key = (
                image_base,
                bin_base,
                func_data[2],
                func_data[3],
                func_data[4],
            )
            target_keys.append(func_key)

    logger.info(
        "Loaded %d target functions in %d binaries.", len(target_keys), len(target_bins)
    )

    # Loading ground truth data
    vuln_map = {
        # FirmAE
        "b33f15": ("804", "alphapd", hex(0x423C6C)),
        "b33f17": ("2", "cgibin", hex(0x40AFB0)),
        "b33f19": ("2", "cgibin", hex(0x40AFB0)),
        "b33f23": ("619", "cgibin", hex(0x18CD0)),
        "b33f28": ("53", "httpd", hex(0x46E578)),
        "b33f35": ("186", "httpd", hex(0x41F6A4)),
        "b33f38": ("104", "httpd", hex(0x369E8)),
        "b33fi10": ("37", "httpd", hex(0x409840)),
        # "b33fi10-1" : ("524", "httpd", hex(0x417f70)),
        "b33fi1": ("118", "httpd", hex(0x405034)),
        "b33fi25": ("2", "cgibin", hex(0x4057A4)),
        "b33fi29-1": ("99", "httpd", hex(0x163DC)),
        "b33fi29-2": ("99", "httpd", hex(0x2A908)),
        "b33fi13": ("510", "webproc", hex(0x401D90)),
        "bof1": ("653", "udhcpd", hex(0x403DE4)),  # IDA cannot process this
        "bof2": ("939", "libleopard.so", hex(0x105A4)),
        "bof3": ("979", "setup.cgi", hex(0x230A0)),
        "bof4": ("896", "rc", hex(0x419034)),
        "bof4-2": ("896", "rc", hex(0x41EB54)),
        "bof5": ("41", "httpd", hex(0x445C04)),
        "rce7": ("939", "ncc", hex(0x463270)),
        "rce7-1": ("939", "ncc", hex(0x4639E8)),

        # baseband
        "B9": (
            "Model D (Old)",
            "modem_unpacked.bin",
            hex(0x40B469BE),
        ),
        "B8": (
            "Model D (Old)",
            "modem_unpacked.bin",
            hex(0x413D6AAC),
        ),
        "B7": (
            "Model D (Old)",
            "modem_unpacked.bin",
            hex(0x413D4C04),
        ),
        "B6": (
            "Model D (Old)",
            "modem_unpacked.bin",
            hex(0x40771A10),
        ),
    }
    ground = {}
    for vuln_key in vuln_map.values():
        ground[vuln_key] = {}

    firmware_info = {}
    first = True
    with open(ground_fname, "r") as f:
        reader = csv.reader(f, delimiter=",", quotechar='"')
        for row in reader:
            # First line contains the name of each column
            if first:
                ground_names = row
                first = False
                continue

            # For the next rows, we store vuln data
            image_idx = row[0]
            image_vendor = row[1]
            image_name = row[2]
            image_arch = row[3]
            image_vulns = row[4]
            vulns = row[10:]
            firmware_info[image_idx] = (image_name, image_vendor, image_arch)
            for idx, vuln in enumerate(vulns):
                if not vuln:
                    continue

                idx = idx + 10  # vuln starts with index 10
                vuln_name = ground_names[idx]
                vuln_key = vuln_map[vuln_name]

                # This is a subset of b33f19
                if vuln_name == "b33f17":
                    continue

                vuln = vuln.split(",")
                assert len(vuln) > 1, row
                bin_name = vuln[0]
                func_addr = vuln[1].lower()

                ground[vuln_key][image_idx] = (bin_name, func_addr)

    # Now check each score files
    total_ranks = []
    for target_idx, target_key in enumerate(sorted(target_keys, key=lambda x: x[0])):
        image_idx = target_key[0]
        bin_name = target_key[1]
        func_addr = hex(target_key[2])
        func_name = target_key[3]
        bin_arch = target_key[4]
        vuln_key = (image_idx, bin_name, func_addr)

        dir_name = "_".join(
            ["scores", image_idx, bin_name, func_addr, func_name, bin_arch]
        )
        dir_name = os.path.join(outdir, config_fname, dir_name)
        os.makedirs(dir_name, exist_ok=True)

        # To test only ground truth
        images_filtered = list(
            filter(lambda x: get_base(x) in ground[vuln_key], images)
        )

        # To test all firmware images
        #        images_filtered = list(filter(
        #            lambda x:
        #            get_base(x) in firmware_info,
        #            images
        #        ))

        # results: image_idx, top_k, results
        results = do_multiprocess(
            check_helper,
            images_filtered,
            chunk_size=1,
            threshold=1,
            initializer=_init_check,
            initargs=(dir_name, firmware_info, ground[vuln_key]),
        )
        results.sort(key=lambda x: int(x[0]))
        ranks = list(map(lambda x: x[1], results))
        if not ranks:
            ranks = np.nan
        else:
            total_ranks.extend(list(map(lambda x: (target_idx, x), ranks)))

        # check if -1 exists
        false_results = list(filter(lambda x: x[1] == -1, results))
        if false_results:
            pp.pprint(results)

        avg_rank = np.mean(ranks)
        print(
            "Target: ",
            image_idx,
            bin_name,
            func_addr,
            func_name,
            bin_arch,
            vuln_name,
            "\tRank: {:.2f} ({})".format(avg_rank, len(ranks)),
        )

        lines = list(map(lambda x: x[2][0], results))
        lines.sort(key=lambda x: float(x[1]), reverse=True)
        # lines = list(filter(lambda x: float(x[1]) > 0.5, lines))
        lines = list(map(lambda x: ",".join(map(str, x)), lines))

        out_fname = dir_name + ".txt"
        columns = [
            "Idx",
            "Score",
            "Ground",
            "Addr",
            "Name",
            "Bin",
            "Arch",
            "Vendor",
            "Firmware",
        ]
        with open(out_fname, "w") as f:
            f.write(",".join(columns) + "\n")
            f.write("\n".join(lines))
        # for line in lines:
        #    print(line)

    for k in [1, 5, 10, 50, 100, 3000]:
        cnt = len(list(filter(lambda x: x[1] <= k, total_ranks)))
        unique_cnt = len(
            set(map(lambda x: x[0], filter(lambda x: x[1] <= k, total_ranks)))
        )
        print(
            "Top-{}: {} {} {:.2f}%".format(
                k, unique_cnt, cnt, float(cnt) / len(total_ranks) * 100
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
    if (
        not opts.image_list
        or not os.path.exists(opts.image_list)
        or not opts.outdir
        or not opts.ground
    ):
        op.print_help()
        exit(1)

    file_handler = logging.FileHandler(os.path.join(opts.outdir, "check_log.txt"))
    logger.addHandler(file_handler)
    logger.info("output directory: %s", opts.outdir)

    check(opts.image_list, opts.outdir, opts.config, opts.ground, opts.debug)
