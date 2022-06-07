package btieval.core;

import binary_type_inference.BinaryTypeInference;
import binary_type_inference.PreservedFunctionList;
import btieval.EvaluatedTypesCollector;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.OSFileNotFoundException;
import ghidra.program.model.listing.Program;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;

public class BTIEval {
  private final Program prog;
  private final BinaryTypeInference ty_inf;
  private final Path outputPath;

  private static final String DEFAULT_TOOL_NAME = "compute_type_differences";

  public BTIEval(Program prog, boolean should_save_output, Path outputPath) {
    this.prog = prog;
    this.ty_inf =
        new BinaryTypeInference(
            this.prog,
            PreservedFunctionList.createFromExternSection(prog),
            new ArrayList<>(),
            new MessageLog() {},
            should_save_output);
    this.outputPath = outputPath;
  }

  private Path getTypeDifferenceToolPath() throws OSFileNotFoundException {
    return Path.of(Application.getOSFile(BTIEval.DEFAULT_TOOL_NAME).getAbsolutePath());
  }

  private Path getOuputFileName() {
    return Path.of(this.outputPath.toString(), this.prog.getName() + "_typeeval.jon");
  }

  public boolean runEvaluation() throws Exception {
    this.ty_inf.produceArtifacts();

    var collector = new EvaluatedTypesCollector(this.prog, this.ty_inf.getWorkingDir());
    collector.generateDWARFConstraints();

    ProcessBuilder bldr =
        new ProcessBuilder(
                this.getTypeDifferenceToolPath().toAbsolutePath().toString(),
                this.ty_inf.getBinaryPath().toAbsolutePath().toString(),
                this.ty_inf.getIROut().toAbsolutePath().toString(),
                this.ty_inf.getLatticeJsonPath().toAbsolutePath().toString(),
                this.ty_inf.getAdditionalConstraintsPath().toAbsolutePath().toString(),
                this.ty_inf.getInterestingTidsPath().toAbsolutePath().toString(),
                collector.getTargetDWARFConsPath().toAbsolutePath().toString(),
                collector.getTargetDWARFLattice().toAbsolutePath().toString(),
                "--out",
                this.getOuputFileName().toAbsolutePath().toString())
            .redirectOutput(new File("/dev/null"))
            .redirectError(new File("/dev/null"));

    var bti = bldr.start();

    return bti.waitFor() == 0;
  }
}
