import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.io.*;
public class DumpInstructions extends GhidraScript {
 public void run() throws Exception {
  PrintWriter w=new PrintWriter(new File(getScriptArgs()[0]));
  InstructionIterator it=currentProgram.getListing().getInstructions(true);
  while(it.hasNext()&&!monitor.isCancelled()) { Instruction i=it.next(); w.println(i.getAddress()+"  "+i); }
  w.close();
 }
}
