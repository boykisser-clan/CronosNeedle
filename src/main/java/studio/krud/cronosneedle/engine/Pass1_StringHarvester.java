package studio.krud.cronosneedle.engine;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;
import studio.krud.cronosneedle.model.Finding;

import java.util.regex.Pattern;

public class Pass1_StringHarvester {

    private static final Pattern RAW_IP_URL = Pattern.compile("https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
    private static final Pattern EXFIL_HOSTS = Pattern.compile(
            "(pastebin\\.com|hastebin\\.com|ghostbin\\.co|rentry\\.co|cdn\\.discordapp\\.com/attachments|discord\\.com/api/webhooks)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern GITHUB_RAW = Pattern.compile("raw\\.githubusercontent\\.com", Pattern.CASE_INSENSITIVE);
    private static final Pattern BASE64_PAYLOAD = Pattern.compile("[A-Za-z0-9+/=]{80,}");
    private static final Pattern HEX_BLOB = Pattern.compile("[0-9a-fA-F]{64,}");
    private static final Pattern SHELL_KEYWORDS = Pattern.compile(
            "(cmd\\.exe /c|/bin/sh -c|/bin/bash|wget |curl |chmod 7)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern DISCORD_BOT_TOKEN = Pattern.compile(
            "(Bot [A-Za-z0-9._\\-]{50,}|[MN][A-Za-z0-9_\\-]{23}\\.[A-Za-z0-9_\\-]{6}\\.[A-Za-z0-9_\\-]{27,})");
    private static final Pattern BTC_WALLET = Pattern.compile("[13][a-km-zA-HJ-NP-Z1-9]{25,34}");
    private static final Pattern ETH_WALLET = Pattern.compile("0x[a-fA-F0-9]{40}");
    private static final Pattern SENSITIVE_PATHS = Pattern.compile(
            "(ops\\.json|server\\.properties|whitelist\\.json|banned-players\\.json|/tmp/|C:\\\\Windows\\\\Temp|AppData\\\\Roaming)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern FAKE_INTERNAL_PKG = Pattern.compile(
            "(org\\.bukkit\\.craftbukkit\\.internal\\.security|net\\.minecraft\\.util\\.encrypt|com\\.mojang\\.authlib\\.inject)",
            Pattern.CASE_INSENSITIVE);

    public void run(AnalysisContext context) {
        for (ClassNode cn : context.getClassMap().values()) {
            for (MethodNode mn : cn.methods) {
                for (AbstractInsnNode insn : mn.instructions) {
                    if (insn instanceof LdcInsnNode ldc) {
                        if (ldc.cst instanceof String str) {
                            context.getHarvestedStrings().add(str);
                            analyzeString(str, cn.name, mn.name, context);
                        }
                    }
                }
            }
        }
    }

    private void analyzeString(String str, String className, String methodName, AnalysisContext context) {
        if (RAW_IP_URL.matcher(str).find()) {
            context.addFinding(Finding.Severity.HIGH, className, methodName,
                    "Raw IP URL detected: " + truncate(str, 80));
        }
        if (EXFIL_HOSTS.matcher(str).find()) {
            context.addFinding(Finding.Severity.HIGH, className, methodName,
                    "Known exfiltration host detected: " + truncate(str, 80));
        }
        if (GITHUB_RAW.matcher(str).find()) {
            context.addFinding(Finding.Severity.MEDIUM, className, methodName,
                    "GitHub raw URL detected: " + truncate(str, 80));
        }
        if (str.length() > 100 && BASE64_PAYLOAD.matcher(str).find()) {
            context.addFinding(Finding.Severity.CRITICAL, className, methodName,
                    "Possible Base64-encoded payload (length=" + str.length() + ")");
        }
        if (HEX_BLOB.matcher(str).find()) {
            context.addFinding(Finding.Severity.HIGH, className, methodName,
                    "Hex blob detected (possible shellcode or key): " + truncate(str, 40) + "...");
        }
        if (SHELL_KEYWORDS.matcher(str).find()) {
            context.addFinding(Finding.Severity.CRITICAL, className, methodName,
                    "Shell command keyword detected: " + truncate(str, 80));
        }
        if (DISCORD_BOT_TOKEN.matcher(str).find()) {
            context.addFinding(Finding.Severity.CRITICAL, className, methodName,
                    "Discord bot token pattern detected");
        }
        if (BTC_WALLET.matcher(str).find()) {
            context.addFinding(Finding.Severity.HIGH, className, methodName,
                    "Bitcoin wallet address detected");
        }
        if (ETH_WALLET.matcher(str).find()) {
            context.addFinding(Finding.Severity.MEDIUM, className, methodName,
                    "Ethereum wallet address detected");
        }
        if (SENSITIVE_PATHS.matcher(str).find()) {
            context.addFinding(Finding.Severity.MEDIUM, className, methodName,
                    "Sensitive file path reference: " + truncate(str, 80));
        }
        if (FAKE_INTERNAL_PKG.matcher(str).find()) {
            context.addFinding(Finding.Severity.HIGH, className, methodName,
                    "Fake internal package string: " + truncate(str, 80));
        }
    }

    private String truncate(String s, int maxLen) {
        return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
    }
}
