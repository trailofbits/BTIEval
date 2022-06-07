package btieval;

import binary_type_inference.BinaryTypeInference;
import binary_type_inference.PreservedFunctionList;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Objects;

public class EvaluatedTypesCollector {
  private final Program prog;
  private final Path output_path;

  public EvaluatedTypesCollector(Program prog, Path output_path) {
    this.prog = prog;
    this.output_path = output_path;
  }

  public Path getTargetDWARFConsPath() {
    return Paths.get(this.output_path.toString(), "dwarf_constraints.pb");
  }

  public Path getTargetDWARFLattice() {
    return Paths.get(this.output_path.toString(), "dwarf_lattice.json");
  }

  void generateTypeSketches() throws IOException {
    var preserved_set = new HashSet<Function>();
    for (var func : this.prog.getFunctionManager().getFunctions(true)) {
      if (!func.isExternal() && func.getSignatureSource() == SourceType.IMPORTED) {
        preserved_set.add(func);
      }
    }

    var preserved_list = new PreservedFunctionList(preserved_set);
    var lat = BinaryTypeInference.createTypeLattice(preserved_list);
    var bldr = lat.getOutputBuilder();
    var os_stream = new FileOutputStream(this.getTargetDWARFConsPath().toFile());
    bldr.buildAdditionalConstraints(os_stream);

    bldr.buildLattice(this.getTargetDWARFLattice().toFile());
  }

  public void generateDWARFConstraints() throws IOException {
    this.applyDWARFAnalysis();
    this.generateTypeSketches();
  }

  void applyDWARFAnalysis() {
    var analysis_manager = AutoAnalysisManager.getAnalysisManager(this.prog);
    var target_analysis = analysis_manager.getAnalyzer("DWARF");
    Objects.requireNonNull(target_analysis);

    analysis_manager.scheduleOneTimeAnalysis(target_analysis, this.prog.getMemory());
    analysis_manager.startAnalysis(TaskMonitor.DUMMY);
    analysis_manager.waitForAnalysis(null, TaskMonitor.DUMMY);
  }
}
