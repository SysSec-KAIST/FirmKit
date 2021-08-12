import os
import sys
import getpass
import time
import tarfile
import yaml
import glob
import numpy as np

np.seterr(divide="ignore", invalid="ignore")

from optparse import OptionParser
from multiprocessing import cpu_count

sys.path.append(os.path.abspath("./TikNib"))
from tiknib.utils import system, do_multiprocess
from tiknib.utils import load_func_data, store_func_data, load_cache
from tiknib.utils import get_func_data_fname
from tiknib.utils import flatten
from tiknib.idascript import IDAScript
from tiknib.feature import FeatureManager
from tiknib.feature.functype import TypeFeature

import logging
import coloredlogs
import pprint as pp

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


def filter_unknown(l):
    return list(filter(lambda x: not x.startswith("sub_"), l))


def get_first_elem(l):
    return list(map(lambda x: x[0], l))


def get_second_elem(l):
    return list(map(lambda x: x[1], l))


def get_base(image):
    return os.path.basename(image).replace(".tar.gz", "")


def get_string_features(func_data):
    features = [
        get_second_elem(func_data["strings"]),
        filter_unknown(get_first_elem(func_data["callers"])),
        filter_unknown(get_first_elem(func_data["callees"])),
        filter_unknown(get_first_elem(func_data["imported_callees"])),
        filter_unknown([func_data["name"]]),
    ]

    features_inter = [
        get_second_elem(func_data["strings_inter"]),
        filter_unknown(get_first_elem(func_data["callers_inter"])),
        filter_unknown(get_first_elem(func_data["callees_inter"])),
        filter_unknown(get_first_elem(func_data["imported_callees_inter"])),
        filter_unknown([func_data["name"]]),
    ]

    return features, features_inter


def get_elf_files(input_dir):
    # This does not follow symbolic links. Note that
    # using system command 'find' is much faster then internal Python scripts
    # when processing a large number of files.
    cmd = "find {0} -type f -exec file {{}} \; | grep ELF".format(input_dir)
    elfs = system(cmd).splitlines()
    elfs = list(map(lambda x: x.split(":")[0], elfs))
    return elfs


def extract_images_helper(image):
    global g_outdir

    if not os.path.exists(image):
        return (image, None)

    # TODO: extend this with extractor.py
    if not image.endswith(".tar.gz"):
        return (image, None)

    image_idx = get_base(image)
    elf_list_dir = os.path.join(g_outdir, "elf_list")
    elf_list_fname = os.path.join(elf_list_dir, "elfs_{}.txt".format(image_idx))

    if not os.path.exists(elf_list_fname):
        image_outdir = os.path.join(g_outdir, image_idx)
        os.makedirs(image_outdir, exist_ok=True)

        def _reset(tarinfo):
            tarinfo.uid = tarinfo.gid = os.getuid()
            tarinfo.uname = tarinfo.gname = getpass.getuser()
            # Some firmware images put strange permission...
            # e.g., TEG-082WS_1.00.010 has "www" directory whose mode is 273.
            if tarinfo.isdir() and tarinfo.mode == 273:
                tarinfo.mode = int("0755", base=8)
            if tarinfo.isfile() and tarinfo.mode == 493:
                tarinfo.mode = int("0644", base=8)
            return tarinfo

        with tarfile.open(image, "r:gz", errorlevel=1) as tar:
            for _file in tar:
                # character device is not necessary
                if _file.isdev() or _file.isblk() or _file.ischr() or _file.isfifo():
                    continue
                _file = _reset(_file)
                try:
                    tar.extract(_file, image_outdir)
                except FileNotFoundError:
                    fname = os.path.join(image_outdir, _file.name)
                    logger.warning("No such file: ", fname)
                except:
                    # for debugging
                    import traceback

                    traceback.print_exc()
                    fname = os.path.join(image_outdir, _file.name)
                    print(fname)
                    import pdb

                    pdb.set_trace()

        # obtain list of files.
        elfs = get_elf_files(image_outdir)
        elfs = list(map(os.path.realpath, elfs))
        with open(elf_list_fname, "w") as f:
            f.write("\n".join(elfs) + "\n")

    return (image, elf_list_fname)


# TODO: handle force correctly
# TODO: handle depth correctly
# TODO: extract features in a matrix form (more space-saving)
def extract_features_helper(bin_path, force=False, depth=1):
    global feature_funcs

    # First check if cache exists
    func_data_fname = get_func_data_fname(bin_path, suffix="_features")
    if not force and os.path.exists(func_data_fname):
        return

    try:
        bin_path, func_data_list = load_func_data(bin_path, suffix="")
    except FileNotFoundError:
        print("No such file: ", bin_path)
        return

    # First, extract features
    fm = FeatureManager()
    func_data_map = {}
    for func_data in func_data_list:
        func_data["bin_path"] = bin_path
        if func_data["seg_name"] == "extern":
            continue
        try:
            features = {}
            for feature in fm.all_features:
                # We do not have type feature. One may extend this with type recovery
                # techniques.
                if feature == TypeFeature:
                    continue
                features.update(feature.get(func_data))
            func_data["feature"] = features
            func_data_map[func_data["name"]] = func_data
        except:
            import traceback

            traceback.print_exc()
            print("Error: ", bin_path)
            return

    # Second, merge features by depth-1
    # TODO: implement inter-procedural feature extraction in TikNib
    for func_data in func_data_list:
        try:
            if func_data["seg_name"] == "extern":
                continue

            features = func_data["feature"].copy()
            strings = func_data["strings"].copy()
            callers = func_data["callers"].copy()
            callees = func_data["callees"].copy()
            imported_callees = func_data["imported_callees"].copy()
            cfg_size = func_data["cfg_size"]

            # Handle functions exist only in current binary
            if func_data["callees"]:
                for callee in func_data["callees"]:
                    callee_name = callee[0]
                    if callee_name not in func_data_map:
                        continue

                    callee_data = func_data_map[callee_name]
                    cfg_size += callee_data["cfg_size"]

                    for feature, val in callee_data["feature"].items():
                        if "_avg_" in feature:
                            continue
                        if feature in features:
                            features[feature] += val
                        else:
                            features[feature] = val

                    strings.extend(callee_data["strings"])
                    callers.extend(callee_data["callers"])
                    callees.extend(callee_data["callees"])
                    imported_callees.extend(callee_data["imported_callees"])

                for feature, val in features.items():
                    if "_avg_" not in feature:
                        continue

                    num_feature = feature.replace("_avg_", "_num_")
                    sum_feature = feature.replace("_avg_", "_sum_")
                    assert num_feature in features or sum_feature in features
                    if num_feature in features:
                        features[feature] = features[num_feature] / float(cfg_size)
                    else:
                        features[feature] = features[sum_feature] / float(cfg_size)

            # TODO: clean up string-related features extraction
            func_data["feature_inter"] = features
            func_data["strings_inter"] = strings
            func_data["callers_inter"] = callers
            func_data["callees_inter"] = callees
            func_data["imported_callees_inter"] = imported_callees
        except:
            import traceback

            traceback.print_exc()

    store_func_data(bin_path, func_data_list, suffix="_features")


def _init_outdir(outdir):
    global g_outdir
    g_outdir = outdir


def extract_images(images, outdir):
    t0 = time.time()
    logger.info("Processing %d images ...", len(images))
    chunk_size = 1.0 * len(images) / cpu_count()
    chunk_size = int(chunk_size)

    elf_list_dir = os.path.join(outdir, "elf_list")
    os.makedirs(elf_list_dir, exist_ok=True)
    results = do_multiprocess(
        extract_images_helper,
        images,
        chunk_size=chunk_size,
        threshold=1,
        initializer=_init_outdir,
        initargs=(outdir,),
    )
    logger.info("Done. (%0.3fs)", (time.time() - t0))
    success = list(filter(lambda x: x[1], results))
    failed = list(filter(lambda x: not x[1], results))
    if failed:
        logger.warning("Failed to extract %d of %d images.", len(failed), len(images))
        failed_images = list(map(lambda x: x[0], failed))
        failed_fname = os.path.join(outdir, "images_failed.txt")
        with open(failed_fname, "w") as f:
            f.write("\n".join(failed_images) + "\n")
        logger.warning("Check: %s.", failed_fname)

    return success


def preprocess_images(image_elf_list, outdir):
    t0 = time.time()
    logger.info("Loading elf files ...")

    # Merge elfs of succesfully extracted images
    elfs = []
    for image, elfs_fname in image_elf_list:
        with open(elfs_fname, "r") as f:
            elfs_tmp = f.read().splitlines()

        elfs.extend(elfs_tmp)

    all_elfs_fname = os.path.join(outdir, "all_elfs.txt")
    with open(all_elfs_fname, "w") as f:
        f.write("\n".join(elfs))
    logger.info("Done. (%0.3fs)", (time.time() - t0))

    # First, process IDA analysis
    idascript = IDAScript(
        idapath="/home/dongkwan/.tools/ida-7.6",
        idc="/home/dongkwan/lastwork/firmkit/fetch_funcdata.py",
        # timeout=60*10,
        # FOR DEBUG
        # force=True,
        # log=True, stdout=True, debug=True,
    )
    logger.info("Processing %d elfs ...", len(elfs))
    idascript.run(all_elfs_fname)
    logger.info("Done. (%0.3fs)", (time.time() - t0))

    # Second, extract features
    logger.info("Extracting features in %d elfs ...", len(elfs))
    do_multiprocess(
        extract_features_helper,
        elfs,
        chunk_size=1,
        threshold=1,
    )
    logger.info("Done. (%0.3fs)", (time.time() - t0))


def relative_difference(a, b):
    max_val = np.maximum(np.absolute(a), np.absolute(b))
    d = np.absolute(a - b) / max_val
    d[np.isnan(d)] = 0  # 0 / 0 = nan -> 0
    d[np.isinf(d)] = 1  # x / 0 = inf -> 1 (when x != 0)
    return d


def relative_distance(X, feature_indices):
    return 1 - (np.sum(X[feature_indices])) / len(feature_indices)


def jaccard_similarity(a, b):
    if not a:
        return 1
    if not b:
        return 0
    s1 = set(a)
    s2 = set(b)
    return float(len(s1.intersection(s2))) / len(s1.union(s2))


def string_similarity(a, b):
    if not a:
        return 1
    if not b:
        return 0
    a_words = flatten(map(lambda x: x.split(), a))
    a_words = list(filter(lambda x: len(x) > 4, a_words))
    b_words = flatten(map(lambda x: x.split(), b))
    b_words = list(filter(lambda x: len(x) > 4, b_words))
    return jaccard_similarity(a_words, b_words)


# TODO: handle force correctly
def calc_metric_helper(arg, force=False):
    global g_target_funcs, g_features, g_feature_indices
    global g_target_strings, g_result_suffix, g_outdir
    image_path, bin_path = arg
    image_idx = get_base(image_path)
    bin_base = bin_path.replace("{}/{}".format(g_outdir, image_idx), "")

    # check if cache exists
    func_data_fname = get_func_data_fname(bin_path, suffix=g_result_suffix)
    if not force and os.path.exists(func_data_fname):
        return

    # Feature loading
    try:
        _, func_data_list = load_func_data(bin_path, suffix="_features")
    except FileNotFoundError:
        print("No such file: ", image_path, bin_path)
        return (image_path, [])

    num_features = len(g_features)
    func_features = {}
    func_strings = {}
    for func_data in func_data_list:
        if not func_data or "feature" not in func_data:
            continue

        func_key = (
            image_idx,
            bin_base,
            func_data["startEA"],
            func_data["name"],
            func_data["arch"],
        )
        if func_key not in func_features:
            func_features[func_key] = [
                np.zeros(num_features, dtype=np.float64),  # depth-0
                np.zeros(num_features, dtype=np.float64),  # depth-1
            ]

        # depth-0 feature
        for feature_idx, feature in enumerate(g_features):
            if feature not in func_data["feature"]:
                continue
            val = func_data["feature"][feature]
            func_features[func_key][0][feature_idx] = val

        if "feature_inter" not in func_data:
            print(image_path, bin_path, func_key)

        # depth-1 feature
        for feature_idx, feature in enumerate(g_features):
            if feature not in func_data["feature_inter"]:
                continue
            val = func_data["feature_inter"][feature]
            func_features[func_key][1][feature_idx] = val

        # String-related features
        # TODO: merge fetching string-related features in extract_features()
        func_strings[func_key] = get_string_features(func_data)

    # Calculating
    results = {}
    for target_key, target_func in sorted(g_target_funcs.items()):
        target_results = []
        target_arch = target_key[-1]
        for func_key, func in sorted(func_features.items()):
            arch = func_key[-1]
            archs = [target_arch.split("_")[0], arch.split("_")[0]]
            archs = "_".join(archs)
            feature_indices = g_feature_indices[archs]

            func_results = [func_key]
            for depth in range(2):
                rdiff = relative_difference(target_func[depth], func[depth])
                rdist = relative_distance(rdiff, feature_indices)

                # match: strings, callers, callees, imported callees, function name
                # We currently focus on depth-0 and depth-1
                str_scores = []
                for str_feature_idx, str_feature in enumerate(
                    g_target_strings[target_key][depth]
                ):
                    str_scores.append(
                        string_similarity(
                            g_target_strings[target_key][depth][str_feature_idx],
                            func_strings[func_key][depth][str_feature_idx],
                        )
                    )
                # score = [rdiff, rdist, str_scores]
                score = [rdist, str_scores]
                func_results.append(score)
            target_results.append(func_results)
        results[target_key] = target_results

    store_func_data(bin_path, results, suffix=g_result_suffix)


# inevitably use globals since it is fast.
def _init_calc(
    target_funcs, features, feature_indices, target_strings, result_suffix, outdir
):
    global g_target_funcs, g_features, g_feature_indices
    global g_target_strings, g_result_suffix, g_outdir
    g_target_funcs = target_funcs
    g_features = features
    g_feature_indices = feature_indices
    g_target_strings = target_strings
    g_result_suffix = result_suffix
    g_outdir = outdir


def load_trained_features(features, pre_trained):
    feature_indices = {}
    logging.info("Loading pre-trained features")
    base_path = pre_trained
    archs = ["arm", "mips", "x86", "mipseb"]
    arch_pairs = ["%s_%s" % (a, b) for a in archs for b in archs]
    # arch_pairs.append('all')

    for arch in arch_pairs:
        outdir = base_path % arch
        logger.info(outdir)
        cache_dir = sorted(glob.glob("{}/*".format(outdir)))[-1]
        roc_max = 0
        for idx in range(10):
            data = load_cache(fname="data-{}".format(idx), cache_dir=cache_dir)
            feature_data, train_data, test_data, test_roc_data = data
            _, _, _, _, train_roc, train_ap, _ = train_data

            if train_roc > roc_max:
                roc_max = train_roc
                data_features = feature_data[0]
                selected = feature_data[1]
                indices = []
                for f in selected:
                    feature = data_features[f]
                    indices.append(features.index(feature))
                feature_indices[arch] = sorted(indices)
    return feature_indices


def merge_results_helper(arg):
    global g_target_keys, g_outdir, g_config_fname, g_result_suffix
    image, elfs_fname = arg
    image_idx = get_base(image)
    target_keys = g_target_keys
    outdir = g_outdir
    config_fname = g_config_fname

    image_scores = {}
    for target_key in target_keys:
        image_scores[target_key] = []

    with open(elfs_fname, "r") as f:
        elfs = f.read().splitlines()

    for elf in elfs:
        try:
            _, results = load_func_data(elf, suffix=g_result_suffix)
        except FileNotFoundError:
            print("No such file: ", image, elf)
            continue
        except EOFError:
            print("Ran out of input: ", image, elf)
            continue

        for target_key, scores in results.items():
            # The result may have additional data.
            if target_key not in image_scores:
                continue
            image_scores[target_key].extend(scores)

    for target_key in sorted(
        target_keys, key=lambda x: get_base(os.path.dirname(x[1]))
    ):
        target_image_idx = target_key[0]
        bin_name = get_base(target_key[1])
        func_addr = hex(target_key[2])
        func_name = target_key[3]
        bin_arch = target_key[4]

        dir_name = "_".join(
            ["scores", target_image_idx, bin_name, func_addr, func_name, bin_arch]
        )
        dir_name = os.path.join(outdir, config_fname, dir_name)
        os.makedirs(dir_name, exist_ok=True)

        score_fname = os.path.join(dir_name, "scores_{}.txt".format(image_idx))

        ## scores: (func_key, [rdiff, rdist, str_scores], ...)
        # scores: (func_key, [rdist, str_scores], ...)
        # str_scores: (score1, score2, score3, ...)
        # Here, we first sort by depth-0 rdist score
        scores = sorted(image_scores[target_key], key=lambda x: x[1][1], reverse=True)
        out_str = ""
        func_keys = get_first_elem(scores)
        for func_idx, func_key in enumerate(func_keys):
            # image_path, bin_path, func_addr, func_name, arch = func_key
            func_scores = scores[func_idx][1:]
            func_key = list(func_key)
            func_key[0] = get_base(func_key[0])
            func_key[2] = hex(func_key[2])
            out_str += ",".join(map(str, func_key))
            # for rdiff, rdist, str_scores in func_scores:
            for rdist, str_scores in func_scores:
                out_str += ":::{:.4f}".format(rdist)
                for str_score in str_scores:
                    out_str += ",{:.4f}".format(str_score)
            out_str += "\n"
        with open(score_fname, "w") as f:
            f.write(out_str)


def _init_merge(target_keys, outdir, config_fname, result_suffix):
    global g_target_keys, g_outdir, g_config_fname, g_result_suffix
    g_target_keys = target_keys
    g_outdir = outdir
    g_config_fname = config_fname
    g_result_suffix = result_suffix


def match_funcs(image_elf_list, outdir, config_fname):
    if not os.path.exists(config_fname):
        logger.error("No such config file: %s", config_fname)
        return

    t0 = time.time()
    logger.info("config file name: %s", config_fname)
    with open(config_fname, "r") as f:
        config = yaml.safe_load(f)

    features = sorted(config["features"])
    num_features = len(features)
    logger.info("%d features", num_features)
    feature_indices = load_trained_features(features, config["pre_trained"])
    logger.info("Loaded pre-trained features:")
    pp.pprint(
        list(
            map(lambda x: (x[0], [features[y] for y in x[1]]), feature_indices.items())
        )
    )

    target_funcs = {}
    target_strings = {}
    target_bins = set()
    for bin_path, funcs in config["target_funcs"].items():
        assert os.path.exists(bin_path), "No such file name: %s" % bin_path
        idascript = IDAScript(
            idapath="/home/dongkwan/.tools/ida-7.6",
            idc="/home/dongkwan/lastwork/firmkit/fetch_funcdata.py",
        )
        idascript.run_helper(bin_path)
        extract_features_helper(bin_path)
        bin_path, func_data_list = load_func_data(bin_path, suffix="_features")
        target_bins.add(bin_path)
        target_data_list = list(
            filter(
                lambda x: x["startEA"] in funcs or x["name"] in funcs, func_data_list
            )
        )

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
            if func_key not in target_funcs:
                target_funcs[func_key] = [
                    np.zeros(num_features, dtype=np.float64),  # depth-0
                    np.zeros(num_features, dtype=np.float64),  # depth-1
                ]

            # depth-0 feature
            for feature_idx, feature in enumerate(features):
                if feature not in func_data["feature"]:
                    continue
                val = func_data["feature"][feature]
                target_funcs[func_key][0][feature_idx] = val

            # depth-1 feature
            for feature_idx, feature in enumerate(features):
                if feature not in func_data["feature_inter"]:
                    continue
                val = func_data["feature_inter"][feature]
                target_funcs[func_key][1][feature_idx] = val

            # String-related features
            # TODO: merge fetching string-related features in extract_features()
            target_strings[func_key] = get_string_features(func_data)
    target_keys = sorted(target_funcs.keys())
    logger.info(
        "Loaded %d target functions in %d binaries.", len(target_keys), len(target_bins)
    )

    # TODO: load features in each elf, image and match.
    logger.info("Loading elf files ...")
    # Merge elfs of succesfully extracted images
    elfs = []
    images = set()
    for image, elfs_fname in image_elf_list:
        images.add(image)
        with open(elfs_fname, "r") as f:
            elfs_tmp = f.read().splitlines()

        for elf in elfs_tmp:
            elfs.append((image, elf))

    # First, process each binaries in parallel. The matching results will be
    # stored at files having suffix "_results"
    logger.info("Matching target functions ...")
    result_suffix = config["result_suffix"]
    do_multiprocess(
        calc_metric_helper,
        elfs,
        chunk_size=1,
        threshold=1,
        initializer=_init_calc,
        initargs=(
            target_funcs,
            features,
            feature_indices,
            target_strings,
            result_suffix,
            outdir,
        ),
    )
    logger.info("Done. (%0.3fs)", time.time() - t0)

    # Next, merge the matching results for each image.
    logger.info("Start collecting the results ...")
    do_multiprocess(
        merge_results_helper,
        image_elf_list,
        pool_size=cpu_count() // 2,
        chunk_size=1,
        threshold=1,
        initializer=_init_merge,
        initargs=(target_keys, outdir, config_fname, result_suffix),
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
        help="give config file (ex) config/config_default.yml",
    )

    (opts, args) = op.parse_args()
    if not opts.image_list or not os.path.exists(opts.image_list) or not opts.outdir:
        op.print_help()
        exit(1)

    os.makedirs(opts.outdir, exist_ok=True)
    file_handler = logging.FileHandler(os.path.join(opts.outdir, "firmkit_log.txt"))
    logger.addHandler(file_handler)
    logger.info("output directory: %s", opts.outdir)

    with open(opts.image_list, "r") as f:
        images = f.read().splitlines()

    if opts.debug:
        logger.warning("Debug mode, select only one image from %d.", len(images))
        images = [images[0]]

    images = extract_images(images, opts.outdir)
    preprocess_images(images, opts.outdir)
    match_funcs(images, opts.outdir, opts.config)
