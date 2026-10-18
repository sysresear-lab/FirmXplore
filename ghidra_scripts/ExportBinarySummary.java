import java.io.FileWriter;
import java.security.MessageDigest;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.FunctionIterator;

public class ExportBinarySummary extends HeadlessScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String output = args.length > 0 ? args[0] : "summary.json";
        int functionCount = 0;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            functions.next();
            functionCount++;
        }
        String json = "{"
            + "\"binary\":\"" + esc(currentProgram.getExecutablePath()) + "\","
            + "\"sha256\":\"" + esc(sha256()) + "\","
            + "\"language\":\"" + esc(currentProgram.getLanguageID().getIdAsString()) + "\","
            + "\"compiler\":\"" + esc(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()) + "\","
            + "\"function_count\":" + functionCount + ","
            + "\"imports\":[],"
            + "\"exports\":[],"
            + "\"interesting_strings\":[],"
            + "\"analysis_timed_out\":" + analysisTimeoutOccurred()
            + "}";
        try (FileWriter writer = new FileWriter(output)) {
            writer.write(json);
        }
    }

    private String sha256() throws Exception {
        byte[] bytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(currentProgram.getExecutablePath()));
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(bytes);
        StringBuilder builder = new StringBuilder();
        for (byte value : hash) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }

    private String esc(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder escaped = new StringBuilder();
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '"':
                    escaped.append("\\\"");
                    break;
                case '\b':
                    escaped.append("\\b");
                    break;
                case '\f':
                    escaped.append("\\f");
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    if (character < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) character));
                    } else {
                        escaped.append(character);
                    }
            }
        }
        return escaped.toString();
    }
}

