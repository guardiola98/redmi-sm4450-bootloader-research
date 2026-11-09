import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
/** Export selected existing functions without executing or redefining firmware. */
public class DumpSelectedFunctions extends GhidraScript {
 public void run() throws Exception {
  String[] args=getScriptArgs();
  DecompInterface d=new DecompInterface(); d.openProgram(currentProgram);
  try(PrintWriter w=new PrintWriter(new File(args[0]))) {
   for(int n=1;n<args.length;n++) {
    Function f=getFunctionAt(toAddr(args[n]));
    w.println("TARGET "+args[n]);
    if(f==null) { w.println("NO FUNCTION AT TARGET"); continue; }
    DecompileResults r=d.decompileFunction(f,30,monitor);
    if(r.decompileCompleted()) w.println(r.getDecompiledFunction().getC());
    else w.println("DECOMPILE FAILED: "+r.getErrorMessage());
   }
  } finally {d.dispose();}
 }
}
