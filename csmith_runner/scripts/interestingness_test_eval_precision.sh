#!/bin/bash

set -e
set -o pipefail

clang -I"$CSMITH_PATH/runtime" -g3 test.c -o test
rm -rf ./tmp_export
rm -rf ./tmp_proj
rm -rf ./ghidra_tmp_proj
mkdir -p ./tmp_proj
mkdir -p ./tmp_export
mkdir -p ./ghidra_tmp_proj
"${GHIDRA_INSTALL_DIR}/support/analyzeHeadless" ./ghidra_tmp_proj TmpProj -import ./test -deleteProject -readOnly -preScript DisableInitialDwarfImport -postScript ExportBTIEvaluationData "./tmp_export" && test -f ./tmp_export/test_typeeval.json > stdout_output
cat stdout_output
grep "ERROR REPORT SCRIPT ERROR" stdout_output
