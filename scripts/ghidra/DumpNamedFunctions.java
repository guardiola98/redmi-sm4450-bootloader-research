import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
import java.util.*;
/** Export only explicitly named functions from a local analysis database. */
public class DumpNamedFunctions extends GhidraScript {
 public void run() throws Exception {
  String[] args=getScriptArgs();
  Set<String> names=new LinkedHashSet<>(Arrays.asList(args).subList(1,args.length));
  DecompInterface d=new DecompInterface(); d.openProgram(currentProgram);
  try(PrintWriter w=new PrintWriter(new File(args[0]))) {
   FunctionIterator functions=currentProgram.getFunctionManager().getFunctions(true);
   while(functions.hasNext() && !monitor.isCancelled()) {
    Function f=functions.next();
    if(!names.remove(f.getName())) continue;
    w.println("FUNCTION "+f.getName()+" "+f.getEntryPoint());
    DecompileResults r=d.decompileFunction(f,30,monitor);
    if(r.decompileCompleted()) w.println(r.getDecompiledFunction().getC());
    else w.println("DECOMPILE FAILED: "+r.getErrorMessage());
   }
   for(String name:names) w.println("NO FUNCTION NAMED "+name);
  } finally {d.dispose();}
 }
}
