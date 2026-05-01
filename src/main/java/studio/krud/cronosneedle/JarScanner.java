package studio.krud.cronosneedle;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import studio.krud.cronosneedle.engine.*;
import studio.krud.cronosneedle.model.Finding;
import studio.krud.cronosneedle.model.ScanResult;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class JarScanner {

    private final boolean verbose;
    private final boolean strict;

    public JarScanner(boolean verbose, boolean strict) {
        this.verbose = verbose;
        this.strict = strict;
    }

    public List<ScanResult> scan(Path target) throws IOException {
        List<ScanResult> results = new ArrayList<>();

        if (Files.isDirectory(target)) {
            try (var stream = Files.walk(target)) {
                var jars = stream
                        .filter(p -> p.toString().endsWith(".jar"))
                        .sorted()
                        .toList();
                for (Path jar : jars) {
                    results.add(scanSingleJar(jar));
                }
            }
        } else if (Files.isRegularFile(target)) {
            results.add(scanSingleJar(target));
        } else {
            throw new IOException("Target not found: " + target);
        }

        return results;
    }

    public List<ScanResult> scanRecursive(Path rootDir) throws IOException {
        List<ScanResult> results = new ArrayList<>();
        try (var stream = Files.walk(rootDir)) {
            var jars = stream
                    .filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".jar"))
                    .sorted()
                    .toList();
            for (Path jar : jars) {
                results.add(scanSingleJar(jar));
            }
        }
        return results;
    }

    private ScanResult scanSingleJar(Path jarPath) throws IOException {
        log("Scanning: " + jarPath.getFileName());

        AnalysisContext context = new AnalysisContext();
        int classCount = 0;

        try (JarFile jar = new JarFile(jarPath.toFile())) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;
                String name = entry.getName();
                if (!name.endsWith(".class")) continue;

                try (InputStream is = jar.getInputStream(entry)) {
                    byte[] bytes = is.readAllBytes();
                    String className = name.replace("/", ".").replace(".class", "");

                    try {
                        ClassReader cr = new ClassReader(bytes);
                        ClassNode cn = new ClassNode();
                        cr.accept(cn, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                        context.getClassMap().put(className, cn);
                        context.getRawClassBytes().put(className, bytes);
                        classCount++;
                    } catch (Exception e) {
                        if (verbose) {
                            log("  [WARN] Failed to parse: " + className + " (" + e.getMessage() + ")");
                        }
                    }
                }
            }
        }

        log("  Loaded " + classCount + " classes");

        // Pass 1: String Harvester
        log("  Pass 1: String Harvester...");
        new Pass1_StringHarvester().run(context);
        log("    Harvested " + context.getHarvestedStrings().size() + " strings, "
                + context.getFindings().size() + " findings so far");

        // Pass 2: Opcode Analyzer
        log("  Pass 2: Opcode Analyzer...");
        new Pass2_OpcodeAnalyzer().run(context);
        log("    Findings: " + context.getFindings().size());

        // Pass 3: Call Graph Tracer
        log("  Pass 3: Call Graph Tracer...");
        new Pass3_CallGraphTracer().run(context);
        log("    Findings: " + context.getFindings().size());

        // Pass 4: Obfuscation Detector
        log("  Pass 4: Obfuscation Detector...");
        new Pass4_ObfuscationDetector().run(context);
        log("    Findings: " + context.getFindings().size());

        // Pass 5: Entropy Analyzer
        log("  Pass 5: Entropy Analyzer...");
        new Pass5_EntropyAnalyzer().run(context);
        log("    Findings: " + context.getFindings().size());

        // Strict mode: downgrade thresholds
        if (strict) {
            for (var f : context.getFindings()) {
                if (f.getSeverity() == Finding.Severity.MEDIUM) {
                    f = new Finding(Finding.Severity.HIGH, f.getClassName(),
                            f.getMethodName(), f.getDescription(), f.getCallChain());
                }
            }
        }

        log("  Passes complete: 5/5");
        log("");

        return new ScanResult(
                jarPath.getFileName().toString(),
                classCount,
                context.getHarvestedStrings().size(),
                5,
                context.getFindings()
        );
    }

    private void log(String msg) {
        if (verbose) {
            System.out.println(msg);
        }
    }
}
