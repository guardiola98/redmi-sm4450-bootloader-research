import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;

/** Static layout for the hash-pinned outer TE in docs/uefi-te-structure.json.
 * Import using BinaryLoader at a7001f38, AARCH64:LE:64:v8A, default compiler.
 * Only config-library provenance is under review; this does not execute code.
 * No relocation or firmware rewriting. Confirm the input SHA-256 beforehand.
 */
public class MapAuditTe extends GhidraScript {
 public void run() throws Exception {
  Memory m = currentProgram.getMemory();
  if (m.getMinAddress().getOffset() != 0xa7001f38L ||
      m.getMaxAddress().getOffset() != 0xa7047fffL ||
      m.getInt(toAddr("a700e0b8")) != 0xf100001f) {
   throw new IllegalArgumentException("Unexpected pinned TE layout/entry bytes");
  }
  // Keep raw loader's memory addresses. Program.setImageBase would rebase
  // blocks too; the TE preferred ImageBase is documented separately.
  m.split(m.getBlock(toAddr("a7001f38")), toAddr("a7002000"));
  m.split(m.getBlock(toAddr("a7002000")), toAddr("a703c000"));
  m.split(m.getBlock(toAddr("a703c000")), toAddr("a7047000"));
  String[] starts = {"a7001f38", "a7002000", "a703c000", "a7047000"};
  String[] names = {"te_header", ".text", ".data", ".reloc"};
  for (int i=0; i<starts.length; i++) {
   MemoryBlock b = m.getBlock(toAddr(starts[i]));
   b.setName(names[i]); b.setRead(true); b.setWrite(i==2); b.setExecute(i==1);
  }
  addEntryPoint(toAddr("a700e0b8"));
  disassemble(toAddr("a700e0b8"));
  createFunction(toAddr("a700e0b8"), "TeEntry");
 }
}
