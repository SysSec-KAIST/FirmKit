#!/bin/bash
set -x

declare -a input_list=(
  "config/firmae/config_firmae_all.yml"
  "config/firmae/config_firmae_arm_mips.yml"
  "config/firmae/config_firmae_arm_x86.yml"
  "config/firmae/config_firmae_arm_mipseb.yml"
  "config/firmae/config_firmae_mips_arm.yml"
  "config/firmae/config_firmae_mips_x86.yml"
  "config/firmae/config_firmae_mips_mipseb.yml"
  "config/firmae/config_firmae_x86_arm.yml"
  "config/firmae/config_firmae_x86_mips.yml"
  "config/firmae/config_firmae_x86_mipseb.yml"
  "config/firmae/config_firmae_mipseb_arm.yml"
  "config/firmae/config_firmae_mipseb_x86.yml"
  "config/firmae/config_firmae_mipseb_mips.yml"
  "config/firmae/config_firmae_mipseb_mipseb.yml"
  "config/firmae/config_firmae_arm_arm.yml"
  "config/firmae/config_firmae_mips_mips.yml"
  "config/firmae/config_firmae_x86_x86.yml"
)
for f in "${input_list[@]}"
do
  # this is feature selecting for openssl, so we use gnu normal dataset
  echo "Processing ${f} ..."
  python helper/test_roc.py \
    --input_list "/home/dongkwan/binkit-dataset/gnu_debug.txt" \
    --train_funcs_limit 200000 \
    --config "${f}"
done
