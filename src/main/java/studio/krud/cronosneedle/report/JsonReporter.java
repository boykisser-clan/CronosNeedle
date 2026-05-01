package studio.krud.cronosneedle.report;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import studio.krud.cronosneedle.model.Finding;
import studio.krud.cronosneedle.model.ScanResult;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class JsonReporter {

    private static final String OUTPUT_FILE = "cronosneedle-report.json";

    public void report(ScanResult result) throws IOException {
        report(result, Path.of(OUTPUT_FILE));
    }

    public void report(ScanResult result, Path outputPath) throws IOException {
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("file", result.getFileName());
        report.put("verdict", result.getVerdict().toString());
        report.put("classesScanned", result.getClassesScanned());
        report.put("stringsHarvested", result.getStringsHarvested());
        report.put("passesCompleted", result.getPassesCompleted());

        List<Map<String, Object>> findingsJson = new ArrayList<>();
        for (Finding f : result.getFindings()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("severity", f.getSeverity().toString());
            entry.put("class", f.getClassName());
            entry.put("method", f.getMethodName());
            entry.put("description", f.getDescription());
            if (f.getCallChain() != null && !f.getCallChain().isEmpty()) {
                entry.put("callChain", f.getCallChain());
            }
            findingsJson.add(entry);
        }
        report.put("findings", findingsJson);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (FileWriter writer = new FileWriter(outputPath.toFile())) {
            gson.toJson(report, writer);
        }

        System.out.println("JSON report written to: " + outputPath);
    }
}
