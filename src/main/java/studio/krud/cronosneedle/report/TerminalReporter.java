package studio.krud.cronosneedle.report;

import studio.krud.cronosneedle.model.Finding;
import studio.krud.cronosneedle.model.ScanResult;

import java.util.List;

public class TerminalReporter {

    private static final String RESET = "\u001B[0m";
    private static final String CRITICAL_COLOR = "\u001B[91m";
    private static final String HIGH_COLOR = "\u001B[93m";
    private static final String MEDIUM_COLOR = "\u001B[96m";
    private static final String LOW_COLOR = "\u001B[97m";

    public void report(ScanResult result) {
        printFindings(result);
        printBanner(result);
    }

    private void printFindings(ScanResult result) {
        List<Finding> findings = result.getFindings();
        if (findings.isEmpty()) {
            System.out.println("No issues detected.");
            System.out.println();
            return;
        }

        // Sort by severity
        findings.stream()
                .sorted((a, b) -> Integer.compare(
                        severityRank(a.getSeverity()),
                        severityRank(b.getSeverity())))
                .forEach(this::printFinding);

        System.out.println();
    }

    private int severityRank(Finding.Severity s) {
        return switch (s) {
            case CRITICAL -> 0;
            case HIGH -> 1;
            case MEDIUM -> 2;
            case LOW -> 3;
        };
    }

    private void printFinding(Finding f) {
        String color = switch (f.getSeverity()) {
            case CRITICAL -> CRITICAL_COLOR;
            case HIGH -> HIGH_COLOR;
            case MEDIUM -> MEDIUM_COLOR;
            case LOW -> LOW_COLOR;
        };

        System.out.println(color + "[" + f.getSeverity() + "] " + f.getClassName());
        if (f.getMethodName() != null && !f.getMethodName().isEmpty()) {
            System.out.print("           \u21B2 Method : " + f.getMethodName());
        }
        System.out.println();
        System.out.println("           \u21B2 Reason : " + f.getDescription() + RESET);
        if (f.getCallChain() != null && !f.getCallChain().isEmpty()) {
            System.out.println(color + "           \u21B2 Chain  : " + f.getCallChain() + RESET);
        }
        for (String d : f.getDetails()) {
            System.out.println(color + "           \u21B2 " + d + RESET);
        }
        System.out.println();
    }

    private void printBanner(ScanResult result) {
        long critical = result.countBySeverity(Finding.Severity.CRITICAL);
        long high = result.countBySeverity(Finding.Severity.HIGH);
        long medium = result.countBySeverity(Finding.Severity.MEDIUM);
        long low = result.countBySeverity(Finding.Severity.LOW);

        String verdictText;
        String verdictColor;
        switch (result.getVerdict()) {
            case MALICIOUS -> {
                verdictText = "\u26D4 MALICIOUS \u2014 DO NOT LOAD";
                verdictColor = CRITICAL_COLOR;
            }
            case SUSPICIOUS -> {
                verdictText = "\u26A0 SUSPICIOUS \u2014 REVIEW MANUALLY";
                verdictColor = HIGH_COLOR;
            }
            case LOW_RISK -> {
                verdictText = "\uD83D\uDFE1 LOW RISK \u2014 INSPECT FLAGGED METHODS";
                verdictColor = MEDIUM_COLOR;
            }
            default -> {
                verdictText = "\u2705 CLEAN";
                verdictColor = RESET;
            }
        }

        int width = 50;
        String border = "\u2550".repeat(width);
        String thinBorder = "\u2500".repeat(width);

        System.out.println("\u2554" + border + "\u2557");
        System.out.println("\u2551     \u26A1 CronosNeedle v2.0  by Krud Studio      \u2551");
        System.out.println("\u2560" + border + "\u2563");
        System.out.println(String.format("\u2551  %-8s: %-38s\u2551", "File",
                truncate(result.getFileName(), 38)));
        System.out.println(String.format("\u2551  %-8s: %-38d\u2551", "Classes",
                result.getClassesScanned()));
        System.out.println(String.format("\u2551  %-8s: %-38d\u2551", "Strings",
                result.getStringsHarvested()));
        System.out.println(String.format("\u2551  %-8s: %-38d\u2551", "Passes",
                result.getPassesCompleted()));
        System.out.println("\u2560" + border + "\u2563");
        System.out.println(String.format("\u2551  %sCRITICAL\u001B[0m : %-3d%sHIGH\u001B[0m : %-3d   %sMED\u001B[0m : %-3d   %sLOW\u001B[0m : %-3d %s\u2551",
                CRITICAL_COLOR, critical, HIGH_COLOR, high, MEDIUM_COLOR, medium, LOW_COLOR, low,
                "\u2551".isEmpty() ? "" : ""));

        System.out.println("\u2560" + border + "\u2563");
        System.out.println("\u2551  " + verdictColor + "VERDICT  : " + verdictText + RESET
                + " ".repeat(Math.max(0, width - 13 - verdictText.length() - 10)) + "\u2551");
        System.out.println("\u255A" + border + "\u255D");
    }

    private String truncate(String s, int maxLen) {
        return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
    }
}
