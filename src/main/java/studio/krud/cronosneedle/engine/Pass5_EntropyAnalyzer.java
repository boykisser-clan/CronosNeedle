package studio.krud.cronosneedle.engine;

import studio.krud.cronosneedle.model.Finding;

import java.util.Set;

public class Pass5_EntropyAnalyzer {

    private static final Set<String> WHITELIST_PACKAGES = Set.of(
            "org/bukkit/",
            "io/papermc/",
            "com/destroystokyo/",
            "net/kyori/",
            "com/mojang/authlib/",
            "net/minecraft/server/",
            "com/google/gson/",
            "com/google/guava/",
            "org/slf4j/",
            "java/util/logging/",
            "com/zaxxer/hikari/",
            "org/sqlite/",
            "com/comphenix/protocol/",
            "me/clip/placeholderapi/",
            "net/luckperms/"
    );

    public void run(AnalysisContext context) {
        for (var entry : context.getRawClassBytes().entrySet()) {
            String className = entry.getKey();
            byte[] bytes = entry.getValue();

            if (isWhitelisted(className)) continue;
            if (bytes.length < 100) continue;

            double entropy = computeShannonEntropy(bytes);

            if (entropy > 7.5) {
                context.addFinding(Finding.Severity.CRITICAL, className, "",
                        "Extremely high entropy (" + String.format("%.2f", entropy) + ") — likely contains encrypted code blob");
            } else if (entropy > 7.2) {
                context.addFinding(Finding.Severity.HIGH, className, "",
                        "High entropy (" + String.format("%.2f", entropy) + ") — possible encrypted/packed payload");
            }
        }
    }

    private double computeShannonEntropy(byte[] bytes) {
        int[] freq = new int[256];
        for (byte b : bytes) {
            freq[b & 0xFF]++;
        }

        double entropy = 0.0;
        double length = bytes.length;
        for (int f : freq) {
            if (f == 0) continue;
            double p = f / length;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private boolean isWhitelisted(String className) {
        for (String pkg : WHITELIST_PACKAGES) {
            if (className.startsWith(pkg)) {
                return true;
            }
        }
        return false;
    }
}
