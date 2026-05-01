package studio.krud.cronosneedle;

import studio.krud.cronosneedle.model.ScanResult;
import studio.krud.cronosneedle.report.JsonReporter;
import studio.krud.cronosneedle.report.TerminalReporter;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public class Main {

    public static void main(String[] args) {
        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }

        String command = args[0];
        if (!"scan".equals(command)) {
            System.err.println("Unknown command: " + command);
            printUsage();
            System.exit(1);
        }

        boolean recursive = false;
        boolean verbose = false;
        boolean json = false;
        boolean strict = false;
        Path target = null;

        int i = 1;
        while (i < args.length) {
            switch (args[i]) {
                case "--recursive", "-r" -> recursive = true;
                case "--verbose", "-v" -> verbose = true;
                case "--json", "-j" -> json = true;
                case "--strict", "-s" -> strict = true;
                default -> {
                    if (target == null) {
                        target = Path.of(args[i]);
                    } else {
                        System.err.println("Unexpected argument: " + args[i]);
                        printUsage();
                        System.exit(1);
                    }
                }
            }
            i++;
        }

        if (target == null) {
            System.err.println("Error: No target file or directory specified.");
            printUsage();
            System.exit(1);
        }

        JarScanner scanner = new JarScanner(verbose, strict);
        TerminalReporter terminalReporter = new TerminalReporter();
        JsonReporter jsonReporter = new JsonReporter();

        try {
            List<ScanResult> results;
            if (recursive) {
                results = scanner.scanRecursive(target);
            } else {
                results = scanner.scan(target);
            }

            if (results.isEmpty()) {
                System.out.println("No JAR files found.");
                System.exit(0);
            }

            for (ScanResult result : results) {
                terminalReporter.report(result);

                if (json) {
                    jsonReporter.report(result);
                }

                // Set exit code based on verdict
                int exitCode = switch (result.getVerdict()) {
                    case MALICIOUS -> 2;
                    case SUSPICIOUS, LOW_RISK -> 1;
                    default -> 0;
                };

                if (results.size() == 1) {
                    System.exit(exitCode);
                }
            }

            // If multiple files, exit with the worst code
            int worstExit = 0;
            for (ScanResult result : results) {
                int code = switch (result.getVerdict()) {
                    case MALICIOUS -> 2;
                    case SUSPICIOUS, LOW_RISK -> 1;
                    default -> 0;
                };
                if (code > worstExit) worstExit = code;
            }
            System.exit(worstExit);

        } catch (IOException e) {
            System.err.println("Error scanning: " + e.getMessage());
            System.exit(3);
        }
    }

    private static void printUsage() {
        System.out.println("""
                CronosNeedle v2.0 — Deep Multi-Pass JAR Malware Analyzer
                by Krud Studio

                Usage:
                  java -jar cronosneedle.jar scan <file.jar> [options]
                  java -jar cronosneedle.jar scan <directory> --recursive

                Options:
                  --recursive, -r    Scan all .jar files in directory tree
                  --verbose, -v      Show detailed analysis progress
                  --json, -j         Generate JSON report (cronosneedle-report.json)
                  --strict, -s       Lower detection thresholds for aggressive scanning

                Exit codes:
                  0 — Clean
                  1 — Suspicious / Low Risk
                  2 — Malicious
                  3 — Error
                """);
    }
}
