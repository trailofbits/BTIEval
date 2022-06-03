package btieval.core;

import binary_type_inference.BinaryTypeInference;
import binary_type_inference.PreservedFunctionList;
import binary_type_inference.TypeAnalyzer;
import btieval.EvaluatedTypesCollector;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

public class BTIEval {
    private final Program prog;
    private final BinaryTypeInference ty_inf;
    private final Path outputPath;


    public BTIEval(Program prog, boolean should_save_output, Path outputPath) {
        this.prog = prog;
        this.ty_inf = new BinaryTypeInference(this.prog, PreservedFunctionList.createFromExternSection(prog) , new ArrayList<>(), new MessageLog() {

        }, should_save_output);
        this.outputPath = outputPath;
    }


    private Path getDWARFConstraintPath() {
        return Paths.get(this.ty_inf.getWorkingDir().toString(), "dwarf_cons.pb");
    }

    public void runEvaluation() throws Exception {
        this.ty_inf.produceArtifacts();

        var collector = new EvaluatedTypesCollector(this.prog, this.getDWARFConstraintPath());
        collector.generateDWARFConstraints();
        
    }


}
