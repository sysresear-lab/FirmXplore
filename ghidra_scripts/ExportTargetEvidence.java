// P06-only experimental evidence export. Does not modify the six standard exports.
// @category FirmXplore.Experimental
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.*;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import com.google.gson.GsonBuilder;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class ExportTargetEvidence extends HeadlessScript {
    private static final String HASH = "8abdb32fee180c6765d4e953b97f1d7e16b6de67271a11d156a541ec1dc26eed";
    private static final int MAX_INSNS = 10000, MAX_OPS = 20000, MAX_VALUES = 50000;
    private static final int MAX_BYTES = 20 * 1024 * 1024;
    private final Map<String, Map<String, Object>> values = new LinkedHashMap<>();
    private final Map<String, List<Object>> uses = new LinkedHashMap<>();

    private Map<String, Object> obj(Object... pairs) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) m.put((String)pairs[i], pairs[i + 1]);
        return m;
    }
    private Object addr(Address a) {
        return a == null ? null : obj("space", a.getAddressSpace().getName(), "offset", a.toString(false));
    }
    private String opId(PcodeOp op) {
        return "ssa:op:" + op.getSeqnum().getTarget().toString() + ":" + op.getSeqnum().getTime();
    }
    private String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte v : b) s.append(String.format("%02x", v & 255));
        return s.toString();
    }
    private String sha(Path path) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }
    private Map<String, Object> state(String status, String reason) {
        return obj("status", status, "reason", reason);
    }
    private Map<String, Object> rawValue(Varnode v) {
        return v == null ? null : obj("storage", addr(v.getAddress()), "size_bytes", v.getSize(),
            "constant", v.isConstant(), "node_class", v.getClass().getName(),
            "ssa_identity", null, "def_use_status", "unavailable",
            "reason", "Raw instruction varnodes are not decompiler SSA values");
    }
    private String value(Varnode v) {
        if (v == null) return null;
        if (!(v instanceof VarnodeAST)) throw new IllegalStateException("Non-AST node in HighFunction");
        String id = "ssa:v:" + ((VarnodeAST)v).getUniqueId();
        if (!values.containsKey(id)) {
            if (values.size() >= MAX_VALUES) throw new IllegalStateException("value_budget_exceeded");
            PcodeOp def = v.getDef();
            values.put(id, obj("value_id", id, "storage", addr(v.getAddress()), "size_bytes", v.getSize(),
                "constant", v.isConstant(), "function_input", v.isInput(),
                "node_class", v.getClass().getName(), "def_op_id", def == null ? null : opId(def),
                "def_origin", "VarnodeAST.getDef; null does not establish an external source"));
            uses.put(id, new ArrayList<>());
        }
        return id;
    }
    private Map<String, Object> instruction(Instruction ins) throws Exception {
        List<Object> refs = new ArrayList<>(), raw = new ArrayList<>();
        Set<String> seenRefs = new HashSet<>();
        boolean callRef = false, rawCall = false;
        for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(ins.getAddress())) {
            String key = r.getFromAddress()+"|"+r.getToAddress()+"|"+r.getReferenceType()+"|"+r.getOperandIndex();
            if (!seenRefs.add(key)) continue;
            Function callee = currentProgram.getFunctionManager().getFunctionAt(r.getToAddress());
            refs.add(obj("from", addr(r.getFromAddress()), "to", addr(r.getToAddress()),
                "reference_type", r.getReferenceType().toString(), "is_call", r.getReferenceType().isCall(),
                "operand_index", r.getOperandIndex(), "callee_entry", callee == null ? null : addr(callee.getEntryPoint()),
                "callee_name", callee == null ? null : callee.getName(),
                "target_resolution", callee == null ? "unresolved_exact_entry" : "database_exact_entry",
                "callee_is_thunk", callee == null ? null : callee.isThunk(),
                "thunk_resolution_status", "unavailable", "thunk_resolution_reason", "Not followed in P06 minimal prototype"));
            callRef |= r.getReferenceType().isCall();
        }
        int index = 0;
        for (PcodeOp op : ins.getPcode()) {
            List<Object> inputs = new ArrayList<>();
            for (int i = 0; i < op.getNumInputs(); i++) inputs.add(rawValue(op.getInput(i)));
            raw.add(obj("raw_op_id", "raw:"+ins.getAddress()+":"+index++, "opcode", op.getMnemonic(),
                "inputs", inputs, "output", rawValue(op.getOutput()), "layer", "raw_instruction_pcode"));
            rawCall |= op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND;
        }
        boolean candidate = ins.getFlowType().isCall() || rawCall || callRef;
        boolean supported = ins.getFlowType().isCall() && rawCall && callRef;
        return obj("instruction_address", addr(ins.getAddress()), "bytes_hex", hex(ins.getBytes()),
            "mnemonic", ins.getMnemonicString(), "display", ins.toString(),
            "flow_type", ins.getFlowType().toString(), "flow_is_call", ins.getFlowType().isCall(),
            "delay_slot_depth", ins.getDelaySlotDepth(), "references", refs, "raw_pcode", raw,
            "callsite_id", candidate ? "insn:"+ins.getAddress() : null,
            "callsite_status", candidate ? (supported ? "observed" : "partial") : "not_a_call_candidate",
            "callsite_reason", candidate ? (supported ? "Instruction flow, raw CALL/CALLIND and call reference agree" :
                "Instruction/raw P-code/reference agreement incomplete; no callee or argument invented") : "No call indicators");
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Expected fresh output path; target is fixed to P06");
        Path output = Paths.get(args[0]);
        if (Files.exists(output)) throw new IllegalArgumentException("Refusing existing output");
        Map<String, Object> root = obj("schema_version", "firmxplore.p06_export.prototype.v1",
            "scope", "P06 only; no taint, memory effects, parameter roles or vulnerability conclusion",
            "id_scope", "IDs are local to this sidecar; qualify with file SHA-256 and JSON Pointer",
            "ghidra_version", Application.getApplicationVersion(), "java_version", System.getProperty("java.version"),
            "expected_sha256", HASH, "expected_entry", "004061f8", "status", "unavailable");
        List<Object> instructions = new ArrayList<>(), ops = new ArrayList<>();
        root.put("instructions", instructions); root.put("ssa_ops", ops);
        root.put("ssa_values", new ArrayList<>());
        root.put("instruction_state", state("unavailable", "Not started"));
        root.put("ssa_state", state("unavailable", "Not started"));
        root.put("budgets", obj("instructions", MAX_INSNS, "ssa_ops", MAX_OPS, "ssa_values", MAX_VALUES,
            "decompile_timeout_seconds", 60, "output_bytes", MAX_BYTES));
        DecompInterface decomp = null;
        try {
            if (!"12.1.3".equals(Application.getApplicationVersion())) throw new IllegalStateException("unsupported_ghidra_version");
            if (!System.getProperty("java.specification.version").equals("21")) throw new IllegalStateException("unsupported_java_version");
            String actualHash = sha(Paths.get(currentProgram.getExecutablePath()));
            root.put("binary", obj("sha256", actualHash, "executable_path", currentProgram.getExecutablePath(),
                "language", currentProgram.getLanguageID().toString(), "compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().toString()));
            if (!HASH.equals(actualHash)) throw new IllegalStateException("binary_hash_mismatch");
            if (!currentProgram.getLanguageID().toString().equals("MIPS:LE:32:default")) throw new IllegalStateException("language_mismatch");
            Function function = currentProgram.getFunctionManager().getFunctionAt(toAddr("004061f8"));
            if (function == null) throw new IllegalStateException("exact_function_entry_not_found");
            root.put("function", obj("name", function.getName(), "entry", addr(function.getEntryPoint()),
                "body_address_count", function.getBody().getNumAddresses(), "signature_source", function.getSignatureSource().toString()));
            boolean analysisTimedOut = analysisTimeoutOccurred();
            root.put("analysis_timed_out", analysisTimedOut);
            InstructionIterator iterator = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                if (instructions.size() >= MAX_INSNS) break;
                instructions.add(instruction(iterator.next()));
            }
            root.put("instruction_state", state(iterator.hasNext() ? "partial" : "observed",
                iterator.hasNext() ? "instruction_budget_exceeded" : "All Listing instructions in exact function body exported"));
            decomp = new DecompInterface();
            if (!decomp.toggleSyntaxTree(true)) throw new IllegalStateException("syntax_tree_toggle_rejected");
            if (!decomp.openProgram(currentProgram)) throw new IllegalStateException("openProgram_false");
            DecompileResults result = decomp.decompileFunction(function, 60, monitor);
            root.put("decompiler", obj("completed", result.decompileCompleted(), "timed_out", result.isTimedOut(),
                "error_message", result.getErrorMessage(), "high_function_present", result.getHighFunction() != null));
            if (!result.decompileCompleted()) throw new IllegalStateException(result.isTimedOut() ? "decompile_timeout" : "decompile_failed");
            HighFunction high = result.getHighFunction();
            if (high == null) throw new IllegalStateException("HighFunction_null");
            Iterator<PcodeOpAST> operations = high.getPcodeOps();
            while (operations.hasNext()) {
                monitor.checkCancelled();
                if (ops.size() >= MAX_OPS) break;
                PcodeOpAST op = operations.next();
                String id = opId(op);
                List<Object> inputs = new ArrayList<>(), actuals = new ArrayList<>();
                for (int i = 0; i < op.getNumInputs(); i++) {
                    String v = value(op.getInput(i)); inputs.add(v);
                    if (v != null) uses.get(v).add(obj("op_id", id, "input_index", i));
                    if ((op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) && i > 0)
                        actuals.add(obj("pcode_input_index", i, "value_id", v,
                            "origin", "decompiler_recovered_input; input[0] is target, no formal role assigned"));
                }
                Instruction linked = currentProgram.getListing().getInstructionAt(op.getSeqnum().getTarget());
                boolean belongs = linked != null && function.getBody().contains(linked.getAddress());
                ops.add(obj("op_id", id, "layer", "decompiler_ssa", "origin", "decompiler_inference",
                    "seq_address", addr(op.getSeqnum().getTarget()), "seq_time", op.getSeqnum().getTime(),
                    "opcode", op.getMnemonic(), "dead", op.isDead(),
                    "block_id", op.getParent() == null ? null : op.getParent().getIndex(),
                    "inputs", inputs, "output", value(op.getOutput()), "recovered_actuals", actuals,
                    "instruction_link", belongs ? "exact_address_in_body" : "unavailable",
                    "instruction_address", belongs ? addr(linked.getAddress()) : null));
            }
            root.put("ssa_state", state(operations.hasNext() ? "partial" : "observed",
                operations.hasNext() ? "ssa_op_budget_exceeded" : "All HighFunction P-code ops exported, including dead/parent state"));
            root.put("status", analysisTimedOut || iterator.hasNext() || operations.hasNext() ? "partial" : "observed");
        } catch (Exception e) {
            root.put("status", instructions.isEmpty() ? "unavailable" : "partial");
            root.put("failure", obj("type", e.getClass().getName(), "message", e.getMessage()));
            if ("unavailable".equals(((Map<?, ?>)root.get("instruction_state")).get("status")))
                root.put("instruction_state", state(instructions.isEmpty() ? "unavailable" : "partial",
                    "Instruction acquisition not completed: "+e.getClass().getName()+": "+e.getMessage()));
            root.put("ssa_state", state("unavailable", e.getClass().getName()+": "+e.getMessage()));
            ops.clear(); values.clear(); uses.clear();
        } finally {
            if (decomp != null) decomp.dispose();
        }
        for (Map.Entry<String, Map<String, Object>> entry : values.entrySet()) {
            entry.getValue().put("uses_in_exported_ops", uses.get(entry.getKey()));
            entry.getValue().put("use_scope", "Derived from ordered inputs of exported SSA ops only");
        }
        root.put("ssa_values", new ArrayList<>(values.values()));
        root.put("limitations", Arrays.asList("No memory SSA, buffer content propagation, API effect model, formal parameter mapping or path feasibility",
            "Function names, boundaries, types and HighFunction are Ghidra analysis results",
            "Recovered CALL inputs do not establish attacker control, reachability or vulnerability",
            "No cross-export ID stability promised; raw instruction values are not SSA"));
        String json = new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(root)+"\n";
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_BYTES) {
            root.put("status", "unavailable"); instructions.clear(); ops.clear(); root.put("ssa_values", new ArrayList<>());
            root.put("instruction_state", state("unavailable", "output_budget_exceeded; records omitted"));
            root.put("ssa_state", state("unavailable", "output_budget_exceeded; records omitted"));
            bytes = (new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(root)+"\n").getBytes(StandardCharsets.UTF_8);
        }
        Path partial = Paths.get(output.toString()+".part");
        Files.write(partial, bytes, StandardOpenOption.CREATE_NEW);
        Files.move(partial, output, StandardCopyOption.ATOMIC_MOVE);
    }
}
