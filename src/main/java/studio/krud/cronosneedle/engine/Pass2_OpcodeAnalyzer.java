package studio.krud.cronosneedle.engine;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import studio.krud.cronosneedle.model.Finding;

import java.util.*;

public class Pass2_OpcodeAnalyzer {

    public void run(AnalysisContext context) {
        for (ClassNode cn : context.getClassMap().values()) {
            for (MethodNode mn : cn.methods) {
                analyzeMethod(cn, mn, context);
            }
        }
    }

    private void analyzeMethod(ClassNode cn, MethodNode mn, AnalysisContext context) {
        List<MethodInsnNode> methodCalls = new ArrayList<>();
        List<FieldInsnNode> fieldAccesses = new ArrayList<>();
        List<LdcInsnNode> ldcNodes = new ArrayList<>();
        Set<String> ldcStrings = new HashSet<>();
        int catchBlocks = 0;
        int emptyCatchBlocks = 0;
        int baloadCount = 0;
        int ixorCount = 0;
        boolean hasRuntimeExec = false;
        boolean hasProcessBuilderInit = false;
        boolean hasProcessBuilderStart = false;
        boolean hasDefineClass = false;
        boolean hasCipherGetInstance = false;
        boolean hasServerSocketInit = false;
        boolean hasUnsafeUsage = false;
        boolean hasURLConnection = false;
        boolean hasOutputStreamWrite = false;
        boolean hasBase64Decode = false;
        boolean hasFileWrite = false;
        boolean hasGetEnvOrProperty = false;
        boolean hasNetworkSendAfterGetEnv = false;
        boolean hasObjectInputStreamReadObject = false;
        boolean hasScriptEngineEval = false;
        boolean hasMethodInvoke = false;
        boolean hasGetDeclaredMethod = false;
        boolean hasSetAccessible = false;
        boolean hasAddShutdownHook = false;
        boolean hasSocketInit = false;
        boolean hasDatagramSocket = false;
        boolean hasFileDelete = false;
        boolean hasThreadSleep = false;
        boolean hasHttpURLConnectionPost = false;
        boolean hasOkHttpPost = false;
        boolean hasZipOutputStream = false;
        boolean hasProxyNewInstance = false;
        boolean hasMethodHandlesFindVirtual = false;
        boolean hasProcessBuilderEnv = false;
        boolean hasClassLoaderDefineClass = false;
        boolean hasURLClassLoaderInit = false;

        boolean isClinit = "<clinit>".equals(mn.name);

        for (AbstractInsnNode insn : mn.instructions) {
            if (insn instanceof MethodInsnNode minsn) {
                methodCalls.add(minsn);
                String owner = minsn.owner;
                String name = minsn.name;

                if ("java/lang/Runtime".equals(owner) && "exec".equals(name)) {
                    hasRuntimeExec = true;
                }
                if ("java/lang/ProcessBuilder".equals(owner) && "<init>".equals(name)) {
                    hasProcessBuilderInit = true;
                }
                if ("java/lang/ProcessBuilder".equals(owner) && "start".equals(name)) {
                    hasProcessBuilderStart = true;
                }
                if ("java/lang/ClassLoader".equals(owner) && "defineClass".equals(name)) {
                    hasDefineClass = true;
                    hasClassLoaderDefineClass = true;
                }
                if ("java/security/SecureClassLoader".equals(owner) && "defineClass".equals(name)) {
                    hasDefineClass = true;
                }
                if ("java/net/URLClassLoader".equals(owner) && "<init>".equals(name)) {
                    hasURLClassLoaderInit = true;
                }
                if ("javax/crypto/Cipher".equals(owner) && "getInstance".equals(name)) {
                    hasCipherGetInstance = true;
                }
                if ("java/net/ServerSocket".equals(owner) && "<init>".equals(name)) {
                    hasServerSocketInit = true;
                }
                if ("sun/misc/Unsafe".equals(owner) || "jdk/internal/misc/Unsafe".equals(owner)) {
                    hasUnsafeUsage = true;
                }
                if ("java/net/HttpURLConnection".equals(owner) && "setRequestMethod".equals(name)) {
                    for (AbstractInsnNode prev = insn; prev != null; prev = prev.getPrevious()) {
                        if (prev instanceof LdcInsnNode ldc && "POST".equals(ldc.cst)) {
                            hasHttpURLConnectionPost = true;
                            break;
                        }
                    }
                }
                if ("okhttp3/OkHttpClient".equals(owner) || "okhttp3/Call".equals(owner)) {
                    if ("newCall".equals(name) || "execute".equals(name) || "enqueue".equals(name)) {
                        hasOkHttpPost = true;
                    }
                }
                if ("java/net/Socket".equals(owner) && "<init>".equals(name)) {
                    hasSocketInit = true;
                }
                if ("java/net/DatagramSocket".equals(owner) && ("<init>".equals(name) || "send".equals(name))) {
                    hasDatagramSocket = true;
                }
                if ("java/nio/file/Files".equals(owner) && "delete".equals(name)) {
                    hasFileDelete = true;
                }
                if ("java/io/File".equals(owner) && "delete".equals(name)) {
                    hasFileDelete = true;
                }
                if ("java/lang/Thread".equals(owner) && "sleep".equals(name)) {
                    hasThreadSleep = true;
                }
                if ("java/util/Base64".equals(owner) || "org/apache/commons/codec/binary/Base64".equals(owner)) {
                    if ("decode".equals(name) || "decodeBase64".equals(name)) {
                        hasBase64Decode = true;
                    }
                }
                if ("java/io/FileOutputStream".equals(owner) && "<init>".equals(name)) {
                    hasFileWrite = true;
                }
                if ("java/io/ObjectInputStream".equals(owner) && "readObject".equals(name)) {
                    hasObjectInputStreamReadObject = true;
                }
                if ("javax/script/ScriptEngine".equals(owner) && "eval".equals(name)) {
                    hasScriptEngineEval = true;
                }
                if ("java/lang/reflect/Method".equals(owner) && "invoke".equals(name)) {
                    hasMethodInvoke = true;
                }
                if ("java/lang/Class".equals(owner) && "getDeclaredMethod".equals(name)) {
                    hasGetDeclaredMethod = true;
                }
                if ("java/lang/reflect/AccessibleObject".equals(owner) && "setAccessible".equals(name)) {
                    hasSetAccessible = true;
                }
                if ("java/lang/Runtime".equals(owner) && "addShutdownHook".equals(name)) {
                    hasAddShutdownHook = true;
                }
                if ("java/lang/ProcessBuilder".equals(owner) && "environment".equals(name)) {
                    hasProcessBuilderEnv = true;
                }
                if ("java/lang/reflect/Proxy".equals(owner) && "newProxyInstance".equals(name)) {
                    hasProxyNewInstance = true;
                }
                if ("java/lang/invoke/MethodHandles$Lookup".equals(owner) && "findVirtual".equals(name)) {
                    hasMethodHandlesFindVirtual = true;
                }
                if ("java/util/zip/ZipOutputStream".equals(owner)) {
                    hasZipOutputStream = true;
                }
                if ("java/net/URLConnection".equals(owner) && "getOutputStream".equals(name)) {
                    hasURLConnection = true;
                }
                if ("java/io/OutputStream".equals(owner) && "write".equals(name)) {
                    hasOutputStreamWrite = true;
                }
                if ("java/lang/System".equals(owner) && ("getenv".equals(name) || "getProperty".equals(name))) {
                    hasGetEnvOrProperty = true;
                }
            }
            if (insn instanceof FieldInsnNode finsn) {
                fieldAccesses.add(finsn);
            }
            if (insn instanceof LdcInsnNode ldc) {
                ldcNodes.add(ldc);
                if (ldc.cst instanceof String s) {
                    ldcStrings.add(s);
                }
            }
            if (insn.getOpcode() == Opcodes.BALOAD || insn.getOpcode() == Opcodes.IALOAD) {
                baloadCount++;
            }
            if (insn.getOpcode() == Opcodes.IXOR) {
                ixorCount++;
            }
        }

        catchBlocks = mn.tryCatchBlocks.size();

        for (TryCatchBlockNode tcb : mn.tryCatchBlocks) {
            boolean empty = isEmptyCatchBlock(mn, tcb.handler);
            if (empty) emptyCatchBlocks++;
        }

        // CRITICAL detections
        if (hasRuntimeExec) {
            context.addFinding(Finding.Severity.CRITICAL, cn.name, mn.name,
                    "Runtime.exec() call detected");
        }
        if (hasProcessBuilderInit && hasProcessBuilderStart) {
            context.addFinding(Finding.Severity.CRITICAL, cn.name, mn.name,
                    "ProcessBuilder used to spawn external process");
        }
        if (hasDefineClass) {
            context.addFinding(Finding.Severity.CRITICAL, cn.name, mn.name,
                    "ClassLoader.defineClass() — dynamic class loading");
        }
        if (hasURLClassLoaderInit) {
            context.addFinding(Finding.Severity.CRITICAL, cn.name, mn.name,
                    "URLClassLoader instantiation — remote class loading possible");
        }
        if (hasURLConnection && hasOutputStreamWrite) {
            context.addFinding(Finding.Severity.CRITICAL, cn.name, mn.name,
                    "URLConnection with OutputStream write — possible data exfiltration");
        }
        if (hasCipherGetInstance && hasDefineClass) {
            context.addFinding(Finding.Severity.CRITICAL, cn.name, mn.name,
                    "Encrypted payload loader pattern: Cipher + defineClass in same method");
        }
        if (hasServerSocketInit) {
            context.addFinding(Finding.Severity.CRITICAL, cn.name, mn.name,
                    "ServerSocket creation — possible reverse shell listener");
        }
        if (hasUnsafeUsage) {
            context.addFinding(Finding.Severity.CRITICAL, cn.name, mn.name,
                    "sun.misc.Unsafe usage — memory manipulation / sandbox escape");
        }
        if (hasProxyNewInstance) {
            context.addFinding(Finding.Severity.CRITICAL, cn.name, mn.name,
                    "Dynamic proxy creation — possible Bukkit interface interception");
        }
        if (hasMethodInvoke && hasGetDeclaredMethod && hasSetAccessible) {
            context.addFinding(Finding.Severity.CRITICAL, cn.name, mn.name,
                    "Reflection access control bypass: getDeclaredMethod + setAccessible + invoke");
        }
        if (isClinit && (hasRuntimeExec || hasProcessBuilderInit || hasServerSocketInit
                || hasURLConnection || hasDefineClass || hasSocketInit)) {
            context.addFinding(Finding.Severity.CRITICAL, cn.name, "<clinit>",
                    "Static initializer contains network/exec call — auto-runs on class load");
        }

        // HIGH detections
        if (hasHttpURLConnectionPost) {
            context.addFinding(Finding.Severity.HIGH, cn.name, mn.name,
                    "HTTP POST request via HttpURLConnection");
        }
        if (hasOkHttpPost) {
            context.addFinding(Finding.Severity.HIGH, cn.name, mn.name,
                    "OkHttpClient network call detected");
        }
        if (hasGetEnvOrProperty && hasNetworkSend(context, methodCalls)) {
            context.addFinding(Finding.Severity.HIGH, cn.name, mn.name,
                    "System env/property read then sent over network — credential exfil");
        }
        if (hasObjectInputStreamReadObject) {
            context.addFinding(Finding.Severity.HIGH, cn.name, mn.name,
                    "ObjectInputStream.readObject() — Java deserialization gadget risk");
        }
        if (hasScriptEngineEval) {
            context.addFinding(Finding.Severity.HIGH, cn.name, mn.name,
                    "ScriptEngine.eval() — arbitrary code execution via scripting");
        }
        if (hasMethodHandlesFindVirtual) {
            context.addFinding(Finding.Severity.HIGH, cn.name, mn.name,
                    "MethodHandles.findVirtual on unknown class — reflective invocation");
        }
        if (hasAddShutdownHook) {
            boolean hasNetworkInShutdown = hasNetworkSend(context, methodCalls);
            if (hasNetworkInShutdown) {
                context.addFinding(Finding.Severity.HIGH, cn.name, mn.name,
                        "Shutdown hook with network send — persistence/exfil on shutdown");
            }
        }
        if (hasProcessBuilderInit && hasProcessBuilderEnv) {
            context.addFinding(Finding.Severity.HIGH, cn.name, mn.name,
                    "ProcessBuilder with environment manipulation before execution");
        }
        if (hasZipOutputStream) {
            context.addFinding(Finding.Severity.HIGH, cn.name, mn.name,
                    "ZipOutputStream file writing — possible exfil archive creation");
        }

        // FileOutputStream with sensitive path
        for (LdcInsnNode ldc : ldcNodes) {
            if (ldc.cst instanceof String s && hasFileWrite) {
                if (s.toLowerCase().contains("ops.json") || s.toLowerCase().contains("server.properties")
                        || s.toLowerCase().contains("whitelist.json") || s.toLowerCase().contains("banned-players")
                        || s.toLowerCase().contains("/tmp/") || s.toLowerCase().contains("appdata")
                        || s.toLowerCase().contains("windows\\temp")) {
                    context.addFinding(Finding.Severity.HIGH, cn.name, mn.name,
                            "FileOutputStream writing to sensitive path: " + s);
                    break;
                }
            }
        }

        // MEDIUM detections
        if (hasSocketInit) {
            for (LdcInsnNode ldc : ldcNodes) {
                if (ldc.cst instanceof String s && !s.equals("localhost") && !s.equals("127.0.0.1") && !s.equals("0.0.0.0")) {
                    context.addFinding(Finding.Severity.MEDIUM, cn.name, mn.name,
                            "Outbound Socket connection to non-localhost: " + s);
                    break;
                }
            }
        }
        if (hasDatagramSocket) {
            context.addFinding(Finding.Severity.MEDIUM, cn.name, mn.name,
                    "DatagramSocket usage — UDP exfiltration possible");
        }
        if (hasFileDelete) {
            context.addFinding(Finding.Severity.MEDIUM, cn.name, mn.name,
                    "File deletion detected — possible evidence destruction");
        }
        if (hasThreadSleep && isEventOrPacketHandler(mn, cn)) {
            context.addFinding(Finding.Severity.MEDIUM, cn.name, mn.name,
                    "Thread.sleep inside event/packet handler — possible timing attack or lag machine");
        }
        if (hasBase64Decode && hasFileWrite) {
            context.addFinding(Finding.Severity.MEDIUM, cn.name, mn.name,
                    "Base64 decode + file write — possible dropped payload");
        }
        if (isClinit && hasFileReadInMethod(mn) && hasNetworkSend(context, methodCalls)) {
            context.addFinding(Finding.Severity.MEDIUM, cn.name, "<clinit>",
                    "Static initializer reads file then sends over network — config exfil");
        }

        // LOW detections
        if (emptyCatchBlocks > 3) {
            context.addFinding(Finding.Severity.LOW, cn.name, mn.name,
                    "Excessive empty catch blocks (" + emptyCatchBlocks + ") — possible error suppression");
        }
        if (mn.name.matches("^[a-zA-Z]{1,2}$") && !isClinit && !"<init>".equals(mn.name)) {
            context.addFinding(Finding.Severity.LOW, cn.name, mn.name,
                    "Suspicious short method name: " + mn.name);
        }
    }

    private boolean isEmptyCatchBlock(MethodNode mn, LabelNode handlerLabel) {
        AbstractInsnNode current = handlerLabel.getNext();
        if (current == null) return true;
        int labelCount = 0;
        while (current != null && labelCount < 2) {
            if (current instanceof LabelNode) {
                labelCount++;
                if (labelCount >= 2) return true;
            } else if (current.getOpcode() >= 0) {
                int op = current.getOpcode();
                if (op != Opcodes.NOP && op != Opcodes.POP && op != Opcodes.POP2) {
                    return false;
                }
            }
            current = current.getNext();
        }
        return true;
    }

    private boolean hasNetworkSend(AnalysisContext context, List<MethodInsnNode> calls) {
        for (MethodInsnNode m : calls) {
            String owner = m.owner;
            String name = m.name;
            if (owner.startsWith("java/net/") || owner.startsWith("okhttp3/")
                    || owner.startsWith("org/apache/http/") || owner.startsWith("javax/net/")) {
                if (name.contains("connect") || name.contains("send") || name.contains("write")
                        || name.contains("post") || name.contains("put") || name.contains("request")
                        || name.contains("openConnection") || name.contains("getOutputStream")
                        || name.equals("execute") || name.equals("enqueue")) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isEventOrPacketHandler(MethodNode mn, ClassNode cn) {
        if (mn.visibleAnnotations != null) {
            for (Object an : mn.visibleAnnotations) {
                if (an instanceof AnnotationNode ann && ann.desc.contains("EventHandler")) return true;
            }
        }
        if (mn.name.toLowerCase().contains("packet") || mn.name.toLowerCase().contains("event")
                || mn.name.toLowerCase().contains("listener") || mn.name.toLowerCase().contains("handle")) {
            return true;
        }
        return false;
    }

    private boolean hasFileReadInMethod(MethodNode mn) {
        for (AbstractInsnNode insn : mn.instructions) {
            if (insn instanceof MethodInsnNode minsn) {
                String owner = minsn.owner;
                String name = minsn.name;
                if (("java/io/FileReader".equals(owner) || "java/nio/file/Files".equals(owner))
                        && (name.equals("<init>") || name.equals("readAllBytes") || name.equals("readAllLines")
                        || name.equals("newInputStream") || name.equals("newBufferedReader"))) {
                    return true;
                }
            }
        }
        return false;
    }
}
