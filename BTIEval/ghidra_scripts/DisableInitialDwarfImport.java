import ghidra.app.script.GhidraScript;

public class DisableInitialDwarfImport extends GhidraScript {

    @Override
    protected void run() throws Exception {
        this.setAnalysisOption(currentProgram, "DWARF", "false");
    }
    
}
