package studio.krud.cronosneedle.engine;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import studio.krud.cronosneedle.model.Finding;

import java.util.*;

public class Pass3_CallGraphTracer {

    private static final Set<String> ENTRY_POINTS = Set.of(
            "onEnable", "onLoad", "onDisable", "<init>", "<clinit>"
    );

    private static final int MAX_DEPTH = 8;

    public void run(AnalysisContext context) {
        buildCallGraph(context);
        identifyEntryPointsAndTrace(context);
    }

    private void buildCallGraph(AnalysisContext context) {
        for (ClassNode cn : context.getClassMap().values()) {
            for (MethodNode mn : cn.methods) {
                String callerKey = cn.name + "." + mn.name + " " + mn.desc;
                for (AbstractInsnNode insn : mn.instructions) {
                    if (insn instanceof MethodInsnNode minsn) {
                        String calleeKey = minsn.owner + "." + minsn.name + " " + minsn.desc;
                        context.addToCallGraph(callerKey, calleeKey);
                    }
                }
            }
        }
    }

    private void identifyEntryPointsAndTrace(AnalysisContext context) {
        Set<String> entryPoints = findEntryPoints(context);
        for (String entry : entryPoints) {
            bfsTrace(entry, context, 0, new HashSet<>(), new ArrayList<>());
        }
    }

    private Set<String> findEntryPoints(AnalysisContext context) {
        Set<String> entryPoints = new LinkedHashSet<>();
        for (ClassNode cn : context.getClassMap().values()) {
            for (MethodNode mn : cn.methods) {
                boolean isEntryPoint = false;
                for (String ep : ENTRY_POINTS) {
                    if (mn.name.equals(ep)) {
                        isEntryPoint = true;
                        break;
                    }
                }
                if (!isEntryPoint && mn.visibleAnnotations != null) {
                    for (AnnotationNode an : mn.visibleAnnotations) {
                        if (an.desc.contains("EventHandler")) {
                            isEntryPoint = true;
                            break;
                        }
                    }
                }
                if (isEntryPoint) {
                    entryPoints.add(cn.name + "." + mn.name + " " + mn.desc);
                }
            }
        }
        return entryPoints;
    }

    private void bfsTrace(String current, AnalysisContext context, int depth,
                          Set<String> visited, List<String> chain) {
        if (depth > MAX_DEPTH || visited.contains(current)) {
            return;
        }
        visited.add(current);
        chain.add(prettyMethodName(current));

        Set<String> callees = context.getCallGraph().get(current);
        if (callees != null) {
            for (String callee : callees) {
                List<String> newChain = new ArrayList<>(chain);
                if (isCriticalCallee(callee)) {
                    newChain.add(prettyMethodName(callee));
                    String chainStr = String.join(" \u2192 ", newChain);
                    context.addFinding(Finding.Severity.CRITICAL,
                            extractClassName(current), extractMethodName(current),
                            "Call chain reaches critical method: " + prettyMethodName(callee),
                            chainStr);
                    return;
                }
                bfsTrace(callee, context, depth + 1, new HashSet<>(visited), newChain);
            }
        }
    }

    private boolean isCriticalCallee(String calleeKey) {
        String parts = calleeKey.split(" ")[0];
        String ownerMethod = parts;

        return ownerMethod.contains("java/lang/Runtime.exec")
                || ownerMethod.contains("java/lang/ProcessBuilder.<init>")
                || ownerMethod.contains("java/lang/ClassLoader.defineClass")
                || ownerMethod.contains("java/security/SecureClassLoader.defineClass")
                || ownerMethod.contains("java/net/URLClassLoader.<init>")
                || ownerMethod.contains("java/net/ServerSocket.<init>")
                || ownerMethod.contains("sun/misc/Unsafe.")
                || ownerMethod.contains("jdk/internal/misc/Unsafe.")
                || ownerMethod.contains("java/net/URLConnection.openConnection")
                || (ownerMethod.contains("javax/crypto/Cipher.getInstance")
                    && hasDefineClassInSameClass(calleeKey));
    }

    private boolean hasDefineClassInSameClass(String calleeKey) {
        String className = calleeKey.substring(0, calleeKey.lastIndexOf('.'));
        return calleeKey.contains("Cipher") && className.contains("ClassLoader");
    }

    private String prettyMethodName(String key) {
        String[] parts = key.split(" ");
        String full = parts[0];
        String[] methodParts = full.split("\\.");
        String methodName = methodParts[methodParts.length - 1];
        String simpleOwner = methodParts[methodParts.length - 2];
        simpleOwner = simpleOwner.substring(simpleOwner.lastIndexOf('/') + 1);
        return simpleOwner + "." + methodName + "()";
    }

    private String extractClassName(String key) {
        String full = key.split(" ")[0];
        return full.substring(0, full.lastIndexOf('.'));
    }

    private String extractMethodName(String key) {
        String full = key.split(" ")[0];
        return full.substring(full.lastIndexOf('.') + 1);
    }
}
