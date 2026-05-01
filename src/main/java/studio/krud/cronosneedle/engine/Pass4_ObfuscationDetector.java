package studio.krud.cronosneedle.engine;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import studio.krud.cronosneedle.model.Finding;

import java.util.*;
import java.util.regex.Pattern;

public class Pass4_ObfuscationDetector {

    private static final Pattern SINGLE_DOUBLE_CHAR = Pattern.compile("^[a-zA-Z]{1,2}[0-9]{0,1}$");
    private static final Pattern REPEATING_CHARS = Pattern.compile("^(.)\\1{3,}$");
    private static final Pattern SHORT_METHOD_NAME = Pattern.compile("^[a-zA-Z]{1,3}[0-9]{0,2}$");

    private static final Set<String> FAKE_BUKKIT_PKGS = Set.of(
            "org.bukkit.craftbukkit.internal",
            "net.minecraft.server.internal"
    );

    public void run(AnalysisContext context) {
        Map<String, Integer> stringDecryptorCalls = new HashMap<>();

        for (ClassNode cn : context.getClassMap().values()) {
            detectShortClassNames(cn, context);
            detectRepeatingMethodNames(cn, context);
            detectByteManipulationHeavy(cn, context);
            detectStringDecryptorPatterns(cn, context, stringDecryptorCalls);
            detectFakeInternalPackages(cn, context);
            detectObfuscationRatio(cn, context);
            detectSyntheticBridgeExcess(cn, context);
        }

        identifyStringDecryptors(context, stringDecryptorCalls);
        crossReferenceObfuscatedWithFindings(context);
    }

    private void detectShortClassNames(ClassNode cn, AnalysisContext context) {
        String simpleName = cn.name.contains("/") ? cn.name.substring(cn.name.lastIndexOf('/') + 1) : cn.name;
        if (SINGLE_DOUBLE_CHAR.matcher(simpleName).matches() && !isInnerClassReasonable(cn)) {
            context.addFinding(Finding.Severity.MEDIUM, cn.name, "",
                    "Single/double character class name detected: " + simpleName);
        }
    }

    private boolean isInnerClassReasonable(ClassNode cn) {
        return (cn.access & Opcodes.ACC_SYNTHETIC) != 0
                || cn.name.contains("$")
                || cn.superName != null && (cn.superName.contains("Enum") || cn.superName.contains("Annotation"));
    }

    private void detectRepeatingMethodNames(ClassNode cn, AnalysisContext context) {
        for (MethodNode mn : cn.methods) {
            if (REPEATING_CHARS.matcher(mn.name).matches()) {
                context.addFinding(Finding.Severity.HIGH, cn.name, mn.name,
                        "Repeating character method name (obfuscation indicator): " + mn.name);
            }
        }
    }

    private void detectByteManipulationHeavy(ClassNode cn, AnalysisContext context) {
        boolean hasLdcStrings = false;
        int baloadCount = 0;
        int ixorCount = 0;

        outer:
        for (MethodNode mn : cn.methods) {
            for (AbstractInsnNode insn : mn.instructions) {
                if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String) {
                    hasLdcStrings = true;
                    break outer;
                }
                int op = insn.getOpcode();
                if (op == Opcodes.BALOAD || op == Opcodes.IALOAD) baloadCount++;
                if (op == Opcodes.IXOR) ixorCount++;
            }
            if (hasLdcStrings) break;
        }

        if (!hasLdcStrings && (baloadCount + ixorCount) > 20) {
            context.addFinding(Finding.Severity.HIGH, cn.name, "",
                    "Heavy byte manipulation without string constants — possible string decryption routine");
        }
    }

    private void detectStringDecryptorPatterns(ClassNode cn, AnalysisContext context,
                                               Map<String, Integer> decryptorCalls) {
        for (MethodNode mn : cn.methods) {
            if ((mn.access & Opcodes.ACC_STATIC) == 0) continue;
            if (!mn.desc.equals("([B)Ljava/lang/String;") && !mn.desc.equals("([I)Ljava/lang/String;")) continue;
            if (mn.instructions.size() < 10) continue;

            boolean hasByteArrayProcessing = false;
            int xorOrAddCount = 0;
            for (AbstractInsnNode insn : mn.instructions) {
                int op = insn.getOpcode();
                if (op == Opcodes.IXOR || op == Opcodes.IADD || op == Opcodes.ISUB) {
                    xorOrAddCount++;
                }
                if (op == Opcodes.BALOAD || op == Opcodes.IALOAD) {
                    hasByteArrayProcessing = true;
                }
            }

            if (hasByteArrayProcessing && xorOrAddCount >= 3) {
                String methodKey = cn.name + "." + mn.name + " " + mn.desc;
                decryptorCalls.putIfAbsent(methodKey, 0);
            }
        }

        for (MethodNode mn : cn.methods) {
            for (AbstractInsnNode insn : mn.instructions) {
                if (insn instanceof MethodInsnNode minsn && (mn.access & Opcodes.ACC_STATIC) != 0) {
                    String callee = minsn.owner + "." + minsn.name + " " + minsn.desc;
                    if (decryptorCalls.containsKey(callee)) {
                        decryptorCalls.merge(callee, 1, Integer::sum);
                    }
                }
            }
        }
    }

    private void identifyStringDecryptors(AnalysisContext context, Map<String, Integer> decryptorCalls) {
        for (Map.Entry<String, Integer> entry : decryptorCalls.entrySet()) {
            if (entry.getValue() > 5) {
                String methodKey = entry.getKey();
                String className = methodKey.substring(0, methodKey.indexOf('.'));
                String methodName = methodKey.substring(methodKey.indexOf('.') + 1, methodKey.indexOf(' '));
                context.addFinding(Finding.Severity.HIGH, className, methodName,
                        "String decryption method called from " + entry.getValue() + " different locations");
            }
        }
    }

    private void detectFakeInternalPackages(ClassNode cn, AnalysisContext context) {
        for (String fakePkg : FAKE_BUKKIT_PKGS) {
            String pkgSlash = fakePkg.replace('.', '/');
            if (cn.name.startsWith(pkgSlash + "/") || cn.name.equals(pkgSlash)) {
                context.addFinding(Finding.Severity.HIGH, cn.name, "",
                        "Class in fake Bukkit/NMS internal package: " + cn.name);
                context.getSuspiciousClasses().add(cn.name);
            }
        }
    }

    private void detectObfuscationRatio(ClassNode cn, AnalysisContext context) {
        int totalMethods = 0;
        int obfuscatedMethods = 0;

        for (MethodNode mn : cn.methods) {
            if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name)) continue;
            totalMethods++;
            if (SHORT_METHOD_NAME.matcher(mn.name).matches()) {
                obfuscatedMethods++;
            }
        }

        if (totalMethods > 3 && (double) obfuscatedMethods / totalMethods > 0.6) {
            context.addFinding(Finding.Severity.HIGH, cn.name, "",
                    "High obfuscation ratio: " + obfuscatedMethods + "/" + totalMethods
                            + " methods have short/random names (" + String.format("%.0f%%", (double) obfuscatedMethods / totalMethods * 100) + ")");
        }
    }

    private void detectSyntheticBridgeExcess(ClassNode cn, AnalysisContext context) {
        int syntheticNonLambda = 0;
        int totalNonLambda = 0;

        for (MethodNode mn : cn.methods) {
            if ((mn.access & Opcodes.ACC_SYNTHETIC) != 0) {
                boolean isLambda = mn.name.contains("lambda$");
                boolean isBridge = (mn.access & Opcodes.ACC_BRIDGE) != 0;
                if (!isLambda) {
                    syntheticNonLambda++;
                }
            }
            boolean isLambda = mn.name.contains("lambda$");
            if (!isLambda) totalNonLambda++;
        }

        if (totalNonLambda > 5 && syntheticNonLambda > totalNonLambda * 0.3) {
            context.addFinding(Finding.Severity.MEDIUM, cn.name, "",
                    "Excessive synthetic methods: " + syntheticNonLambda + "/" + totalNonLambda + " non-lambda methods are synthetic");
        }
    }

    private void crossReferenceObfuscatedWithFindings(AnalysisContext context) {
        for (Finding f : context.getFindings()) {
            if (f.getSeverity() == Finding.Severity.HIGH || f.getSeverity() == Finding.Severity.MEDIUM) {
                String cls = f.getClassName();
                if (isObfuscatedClass(cls, context)) {
                    if (f.getSeverity() != Finding.Severity.CRITICAL) {
                        context.getSuspiciousClasses().add(cls);
                    }
                }
            }
        }

        List<Finding> toAdd = new ArrayList<>();
        for (String suspicious : context.getSuspiciousClasses()) {
            long findingCount = context.getFindings().stream()
                    .filter(f -> f.getClassName().equals(suspicious)).count();
            if (findingCount >= 3) {
                boolean alreadyHas = context.getFindings().stream()
                        .anyMatch(f -> f.getClassName().equals(suspicious)
                                && f.getDescription().contains("obfuscation")
                                && f.getSeverity() == Finding.Severity.CRITICAL);
                if (!alreadyHas) {
                    toAdd.add(new Finding(Finding.Severity.CRITICAL, suspicious, "",
                            "Obfuscated class with " + findingCount + " suspicious findings — high probability of malicious code"));
                }
            }
        }
        for (Finding f : toAdd) {
            context.addFinding(f);
        }
    }

    private boolean isObfuscatedClass(String className, AnalysisContext context) {
        ClassNode cn = context.getClassMap().get(className);
        if (cn == null) return false;
        int shortMethods = 0;
        int total = 0;
        for (MethodNode mn : cn.methods) {
            if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name)) continue;
            total++;
            if (SHORT_METHOD_NAME.matcher(mn.name).matches() || REPEATING_CHARS.matcher(mn.name).matches()) {
                shortMethods++;
            }
        }
        return total > 2 && (double) shortMethods / total > 0.4;
    }
}
