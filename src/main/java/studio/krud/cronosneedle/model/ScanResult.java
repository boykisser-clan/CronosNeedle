package studio.krud.cronosneedle.model;

import java.util.ArrayList;
import java.util.List;

public class ScanResult {
    private final String fileName;
    private final int classesScanned;
    private final int stringsHarvested;
    private final int passesCompleted;
    private final List<Finding> findings;
    private Verdict verdict;

    public enum Verdict {
        CLEAN, LOW_RISK, SUSPICIOUS, MALICIOUS
    }

    public ScanResult(String fileName, int classesScanned, int stringsHarvested,
                      int passesCompleted, List<Finding> findings) {
        this.fileName = fileName;
        this.classesScanned = classesScanned;
        this.stringsHarvested = stringsHarvested;
        this.passesCompleted = passesCompleted;
        this.findings = findings;
        this.verdict = computeVerdict();
    }

    private Verdict computeVerdict() {
        long critical = findings.stream().filter(f -> f.getSeverity() == Finding.Severity.CRITICAL).count();
        long high = findings.stream().filter(f -> f.getSeverity() == Finding.Severity.HIGH).count();
        long medium = findings.stream().filter(f -> f.getSeverity() == Finding.Severity.MEDIUM).count();

        if (critical > 0) return Verdict.MALICIOUS;
        if (high >= 2) return Verdict.SUSPICIOUS;
        if (medium > 0) return Verdict.LOW_RISK;
        return Verdict.CLEAN;
    }

    public String getFileName() { return fileName; }
    public int getClassesScanned() { return classesScanned; }
    public int getStringsHarvested() { return stringsHarvested; }
    public int getPassesCompleted() { return passesCompleted; }
    public List<Finding> getFindings() { return findings; }
    public Verdict getVerdict() { return verdict; }

    public long countBySeverity(Finding.Severity severity) {
        return findings.stream().filter(f -> f.getSeverity() == severity).count();
    }

    public List<Finding> getBySeverity(Finding.Severity severity) {
        return findings.stream().filter(f -> f.getSeverity() == severity).toList();
    }
}
