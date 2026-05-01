package studio.krud.cronosneedle.engine;

import org.objectweb.asm.tree.ClassNode;
import studio.krud.cronosneedle.model.Finding;

import java.util.*;

public class AnalysisContext {
    private final Map<String, ClassNode> classMap = new LinkedHashMap<>();
    private final Map<String, Set<String>> callGraph = new LinkedHashMap<>();
    private final List<String> harvestedStrings = new ArrayList<>();
    private final List<Finding> findings = new ArrayList<>();
    private final Set<String> suspiciousClasses = new HashSet<>();
    private final Map<String, byte[]> rawClassBytes = new HashMap<>();

    public Map<String, ClassNode> getClassMap() { return classMap; }
    public Map<String, Set<String>> getCallGraph() { return callGraph; }
    public List<String> getHarvestedStrings() { return harvestedStrings; }
    public List<Finding> getFindings() { return findings; }
    public Set<String> getSuspiciousClasses() { return suspiciousClasses; }
    public Map<String, byte[]> getRawClassBytes() { return rawClassBytes; }

    public void addFinding(Finding.Severity severity, String className, String methodName, String description) {
        Finding f = new Finding(severity, className, methodName, description);
        findings.add(f);
        if (severity == Finding.Severity.CRITICAL || severity == Finding.Severity.HIGH) {
            suspiciousClasses.add(className);
        }
    }

    public void addFinding(Finding.Severity severity, String className, String methodName, String description, String callChain) {
        Finding f = new Finding(severity, className, methodName, description, callChain);
        findings.add(f);
        if (severity == Finding.Severity.CRITICAL || severity == Finding.Severity.HIGH) {
            suspiciousClasses.add(className);
        }
    }

    public void addFinding(Finding finding) {
        findings.add(finding);
        if (finding.getSeverity() == Finding.Severity.CRITICAL || finding.getSeverity() == Finding.Severity.HIGH) {
            suspiciousClasses.add(finding.getClassName());
        }
    }

    public void addToCallGraph(String caller, String callee) {
        callGraph.computeIfAbsent(caller, k -> new LinkedHashSet<>()).add(callee);
    }

    public int criticalCount() {
        return (int) findings.stream().filter(f -> f.getSeverity() == Finding.Severity.CRITICAL).count();
    }

    public int highCount() {
        return (int) findings.stream().filter(f -> f.getSeverity() == Finding.Severity.HIGH).count();
    }

    public int mediumCount() {
        return (int) findings.stream().filter(f -> f.getSeverity() == Finding.Severity.MEDIUM).count();
    }

    public int lowCount() {
        return (int) findings.stream().filter(f -> f.getSeverity() == Finding.Severity.LOW).count();
    }
}
