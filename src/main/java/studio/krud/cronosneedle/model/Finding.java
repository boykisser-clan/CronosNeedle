package studio.krud.cronosneedle.model;

import java.util.ArrayList;
import java.util.List;

public class Finding {
    public enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW
    }

    private final Severity severity;
    private final String className;
    private final String methodName;
    private final String description;
    private String callChain;
    private final List<String> details = new ArrayList<>();

    public Finding(Severity severity, String className, String methodName, String description) {
        this.severity = severity;
        this.className = className;
        this.methodName = methodName;
        this.description = description;
    }

    public Finding(Severity severity, String className, String methodName, String description, String callChain) {
        this(severity, className, methodName, description);
        this.callChain = callChain;
    }

    public Severity getSeverity() { return severity; }
    public String getClassName() { return className; }
    public String getMethodName() { return methodName; }
    public String getDescription() { return description; }
    public String getCallChain() { return callChain; }
    public void setCallChain(String callChain) { this.callChain = callChain; }
    public List<String> getDetails() { return details; }

    public Finding addDetail(String detail) {
        details.add(detail);
        return this;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(severity).append("] ").append(className);
        if (methodName != null && !methodName.isEmpty()) {
            sb.append(" → ").append(methodName);
        }
        sb.append("\n           ↳ Reason : ").append(description);
        if (callChain != null && !callChain.isEmpty()) {
            sb.append("\n           ↳ Chain  : ").append(callChain);
        }
        for (String d : details) {
            sb.append("\n           ↳ ").append(d);
        }
        return sb.toString();
    }
}
