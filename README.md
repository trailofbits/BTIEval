# BTIEval
Tooling for evaluating BTI soundness and precision on a dataset of binaries.

The plugin can be installed via gradle `./gradlew install`.

If you already have BTIGhidra or BTIEval installed you may need to enable autoremove: `./gradlew install -PBTI_AUTO_REMOVE -PBTIEVAL_AUTO_REMOVE`

The plugin is run through a preScript that effects DWARF settings and a postScript that does the export:

`<GHIDRA_INSTALL_DIR>/support/analyzeHeadless /tmp/tmp_proj TmpProj -import <target_binary or directory of target binaries> -preScript DisableInitialDwarfImport -postScript ExportBTIEvaluationData "<outdir>" -readOnly -deleteProject`

The above command will use /tmp/tmp_proj as the ghidra project and delete the project after running. The target binaries will be imported and then analyzed with BTIGhidra. Evaluation data will be dumped to <outdir>/<binary_name>_typeeval.json for all target binaries. 
