#!/bin/bash
set -x

declare -a input_list=(
  "config/firmae_gcc/config_firmae_gcc_all.yml"
  "config/firmae_gcc/config_firmae_gcc_arm_mips.yml"
  "config/firmae_gcc/config_firmae_gcc_arm_x86.yml"
  "config/firmae_gcc/config_firmae_gcc_arm_mipseb.yml"
  "config/firmae_gcc/config_firmae_gcc_mips_arm.yml"
  "config/firmae_gcc/config_firmae_gcc_mips_x86.yml"
  "config/firmae_gcc/config_firmae_gcc_mips_mipseb.yml"
  "config/firmae_gcc/config_firmae_gcc_x86_arm.yml"
  "config/firmae_gcc/config_firmae_gcc_x86_mips.yml"
  "config/firmae_gcc/config_firmae_gcc_x86_mipseb.yml"
  "config/firmae_gcc/config_firmae_gcc_mipseb_arm.yml"
  "config/firmae_gcc/config_firmae_gcc_mipseb_x86.yml"
  "config/firmae_gcc/config_firmae_gcc_mipseb_mips.yml"
  "config/firmae_gcc/config_firmae_gcc_mipseb_mipseb.yml"
  "config/firmae_gcc/config_firmae_gcc_arm_arm.yml"
  "config/firmae_gcc/config_firmae_gcc_mips_mips.yml"
  "config/firmae_gcc/config_firmae_gcc_x86_x86.yml"
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
