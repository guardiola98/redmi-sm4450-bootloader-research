import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
public class DumpFunctions extends GhidraScript {
 public void run() throws Exception {
  DecompInterface d=new DecompInterface(); d.openProgram(currentProgram);
  PrintWriter w=new PrintWriter(new File(getScriptArgs()[0]));
  FunctionIterator fs=currentProgram.getFunctionManager().getFunctions(true);
  while(fs.hasNext()&&!monitor.isCancelled()) { Function f=fs.next(); w.println("\n// "+f.getEntryPoint()); DecompileResults r=d.decompileFunction(f,30,monitor); if(r.decompileCompleted()) w.println(r.getDecompiledFunction().getC()); }
  w.close(); d.dispose();
 }
}
