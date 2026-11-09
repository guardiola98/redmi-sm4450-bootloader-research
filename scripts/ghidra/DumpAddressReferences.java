import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;
/** Offline reference evidence for explicit addresses; no firmware execution. */
public class DumpAddressReferences extends GhidraScript {
 public void run() throws Exception {
  String[] args=getScriptArgs();
  PrintWriter w=new PrintWriter(new File(args[0]));
  DecompInterface d=new DecompInterface(); d.openProgram(currentProgram);
  HashSet<Address> done=new HashSet<>();
  for(int n=1;n<args.length;n++) {
   Address a=toAddr(args[n]); w.println("TARGET "+a);
   for(Reference r:getReferencesTo(a)) {
    w.println(r.toString());
    Function f=getFunctionContaining(r.getFromAddress());
    if(f!=null && done.add(f.getEntryPoint())) {
     w.println("FUNCTION "+f.getEntryPoint());
     DecompileResults result=d.decompileFunction(f,20,monitor);
     if(result.decompileCompleted()) w.println(result.getDecompiledFunction().getC());
    }
   }
  }
  d.dispose();w.close();
 }
}
