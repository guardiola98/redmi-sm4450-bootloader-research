import ghidra.app.script.GhidraScript;
/** Decode explicit verified entry addresses in the analysis database only. */
public class DisassembleAddresses extends GhidraScript {
 public void run() throws Exception {
  for(String arg:getScriptArgs()) {
   boolean ok=disassemble(toAddr(arg));
   println("STATIC DISASSEMBLY "+arg+" "+ok);
  }
 }
}
