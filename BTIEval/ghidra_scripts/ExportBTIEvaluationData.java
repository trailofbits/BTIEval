import btieval.core.BTIEval;
import ghidra.app.script.GhidraScript;
import java.nio.file.Path;

public class ExportBTIEvaluationData extends GhidraScript {
  @Override
  protected void run() throws Exception {
    var outputPath = this.getScriptArgs()[0];
    var eval = new BTIEval(this.currentProgram, true, Path.of(outputPath));
    var success = eval.runEvaluation();
    if (!success) {
      printerr("Failure exporting: " + currentProgram.getName());
    }
  }
}
