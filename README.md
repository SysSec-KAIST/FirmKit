# Description
FirmKit is an IoT vulnerability analysis tool based on binary code similarity
analysis (BCSA). FirmKit includes **ground truth vulnerabilities** in custom
binaries, such as CGI binaries, for the top eight wireless router and IP camera
vendors.

Currently, the FirmKit utilizes
[TikNib](https://github.com/SoftSec-KAIST/TikNib), which is a simple
interpretable BCSA tool. In addition to TikNib's numeric presemantic features,
FirmKit implements two additional features based on heuristic knowledge. Through
empirical analysis of diverse binaries in our previous studies, we discovered
that IoT binaries frequently contain function names. Thus, rather than comparing
abstracted numeric features, we can directly compare caller and callee names.
For example, we can use the names of internal and library functions instead of
the numbers of callers and callees.
Additionally, we discovered that data strings contained in IoT binaries often
contain useful information. CGI binaries include hard-coded strings for parsing
URLs, such as HTTP, POST, answer, or password. Therefore, we can use these
strings to compute the similarity score. Therefore, we chose to use 1) the
strings to which the function refers and 2) the names of the callee functions.

Firmkit computes the string similarity score between two heuristic features
using a Jaccard index. Then, the similarity scores of these two heuritic
features are averaged with the score obtained by numeric presemantic features.

For more details, please check [my thesis
paper](https://0xdkay.me/pub/2022/kim-phdthesis2022.pdf) (Chapter 6).


# Ground Truth Vulnerability Dataset
To build the ground truth vulnerability dataset, we manually marked the
addresses of vulnerable functions identified in previous studies,
[FirmAE](https://github.com/pr0v3rbs/FirmAE) and
[BaseSpec](https://github.com/SysSec-KAIST/BaseSpec).

For each vulnerability, we manually analyzed the binaries in the firmware images
using IDA Pro and obtained the addresses of the vulnerable functions. We
excluded functions that IDA Pro was unable to analyze. As a result, the final
number of vulnerabilities differs from the number discovered in the previous
studies.

For more information, please check the [ground_truth](/ground_truth) directory
or [Ground Truth Results.xlsx](/ground_truth/Ground_Truth_Results.xlsx).
Baseband binary names are anonymized upon the vendor's request.

**You need to keep the format correctly!**

For the OpenSSL vulnerabilities, we utilized the ASE dataset of
[BinKit](https://github.com/SoftSec-KAIST/BinKit).


# How to use

## Extract firmware images using FirmAE (Optional)

First, target firmware images should be unpacke using
[FirmAE](https://github.com/pr0v3rbs/FirmAE).


## Prepare presemantic features using BinKit and TikNib (Optional)

Next, we train [TikNib](https://github.com/SoftSec-KAIST/TikNib) to select
numeric presemantic features for target compiler options and architectures. In
our experiments, we used three architectures (arm, mips, x86 at 32 bits), two
optimization levels (O2, O3), and four compilers (gcc-4.9.4, gcc-8.2.0,
clang-4.0, calng-7.0). Please check [/config/firmae_gcc](/config/firmae_gcc).

For building the cross-compiling environment and dataset, we used
[BinKit](https://github.com/SoftSec-KAIST/BinKit).

To see the scripts used for this step, please check
[run_firmae_gcc_roc.sh](/helper/run_firmae_gcc_roc.sh). The shell scripts are
used when running TikNib. Please setup right paths for them.


## Run FirmKit
We assume that binaries in a target dataset is already unpacked.

Please replace the values in the config file correctly. For example, please
check
[/config/config_openssl_heartbeat.yml](/config/config_openssl_heartbeat.yml).
For the target vulnerable functions in this configuration, we used the OpenSSL
binaries in the ASE dataset of
[BinKit](https://github.com/SoftSec-KAIST/BinKit).

First, FirmKit extracts .tar.gz files for processing the FirmAE dataset.
For the BaseSpec dataset, it does not conduct this.

Then, FirmKit processes the binaries in a target dataset using IDA Pro.
For this, we slightly modified the `fetch_funcdata_v7.5.py` of
[TikNib](https://github.com/SoftSec-KAIST/TikNib). Please check
[fetch_funcdata.py](/helper/fetch_funcdata.py). We used IDA Pro v7.6.

Next, FirmKit extracts the features selected in the previous step, from the
binaries in a target dataset. If you skipped the previous step, you need to
select your own features in the config file. Please check
[config_firmae_gcc.yml](/config/config_firmae_gcc.yml) for example.

Finally, FirmKit calculates the similarity score.

All above steps is done by running below commands.

```bash
# For testing firmae vulnerabilities
$ python firmkit_firmae.py \
    --image_list helper/images_firmae.txt \
    --outdir output \
    --config config/config_firmae_gcc.yml

# For testing openssl CVE-2014-0160 (Heartbleed) in the firmae dataset
$ python firmkit_firmae.py \
    --image_list helper/images_firmae.txt \
    --outdir output \
    --config config/config_openssl_heartbeat.yml

# For testing openssl CVE-2015-1791 in firmae dataset
$ python firmkit_firmae.py \
    --image_list helper/images_firmae.txt \
    --outdir output \
    --config config/config_openssl_vulseeker.yml

# For testing basespec vulnerabilities
$ python firmkit_basespec.py \
    --image_list helper/images_basespec.txt \
    --outdir output_basepsec \
    --config config/config_basespec.yml
```

To check the similarity scores in a nice format, please check the below
commands. Notably, `check_score_openssl.py` averages all similarity scores and
computes the results.

```bash
# For checking firmae vulnerabilities
$ python check_score.py \
    --image_list helper/images_firmae.txt \
    --outdir output \
    --config config/config_firmae_gcc.yml \
    --ground ground_truth/ground_truth_firmae.csv

# For checking openssl CVE-2014-0160 (Heartbleed) in the firmae dataset
$ python check_score_openssl.py \
    --image_list helper/images_firmae.txt \
    --outdir output \
    --config config/config_openssl_heartbeat.yml

# For checking openssl CVE-2015-1791 in firmae dataset
$ python check_score_openssl.py \
    --image_list helper/images_firmae.txt \
    --outdir output \
    --config config/config_openssl_vulseeker.yml

# For checking basespec vulnerabilities
$ python check_score.py \
    --image_list helper/images_basespec.txt \
    --outdir output_basepsec \
    --config config/config_basespec.yml \
    --ground ground_truth/ground_truth_basespec.csv
```

## Results
The results will be stored in a comma separated file in the output directory. An
example of the result file would be [example_104.csv](/helper/example_104.csv).

For the full results, please check [Similarity Matching
Results.xlsx](/helper/Similarity_Matching_Results.xlsx).


# TODO
Currently, to fully utilize FirmKit, the experimental environment should be set
up first. In the next release we need to automate this procedure with more kind
descriptions.


# Issues

### Tested environment
We ran all our experiments on a server equipped with four Intel Xeon E7-8867v4
2.40 GHz CPUs (total 144 cores), 896 GB DDR4 RAM, and 4 TB SSD. We setup Ubuntu
18.04.5 LTS with IDA Pro v7.6 and Python 3.8.9 on the server.

# Authors
This project has been conducted by the below authors at KAIST.
* [Dongkwan Kim](https://0xdkay.me/)

# Citation
We would appreciate if you consider citing the previous papers,
[FirmAE](https://github.com/pr0v3rbs/FirmAE),
[BaseSpec](https://github.com/SysSec-KAIST/BaseSpec),
[BinKit](https://github.com/SoftSec-KAIST/BinKit) &
[TikNib](https://github.com/SoftSec-KAIST/TikNib).

```bibtex
@inproceedings{kim:2020:firmae,
  author = {Mingeun Kim and Dongkwan Kim and Eunsoo Kim and Suryeon Kim and Yeongjin Jang and Yongdae Kim},
  title = {{FirmAE}: Towards Large-Scale Emulation of IoT Firmware for Dynamic Analysis},
  booktitle = {Annual Computer Security Applications Conference (ACSAC)},
  year = 2020,
  month = dec,
  address = {Online}
}

@article{kim:2021:basespec,
  author = {Eunsoo Kim and Dongkwan Kim and CheolJun Park and Insu Yun and Yongdae Kim},
  title = {{BaseSpec}: Comparative Analysis of Baseband Software and Cellular Specifications for L3 Protocols},
  booktitle = {Proceedings of the 2021 Annual Network and Distributed System Security Symposium (NDSS)},
  year = 2021,
  month = feb,
  address = {Online}
}

@article{kim:2020:binkit,
  author = {Dongkwan Kim and Eunsoo Kim and Sang Kil Cha and Sooel Son and Yongdae Kim},
  title = {Revisiting Binary Code Similarity Analysis using Interpretable Feature Engineering and Lessons Learned},
  eprint={2011.10749},
  archivePrefix={arXiv},
  primaryClass={cs.SE}
  year = {2020},
}
```
