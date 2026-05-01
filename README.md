<div align="center">

# ⚡ CronosNeedle v2.0

### Deep Multi-Pass ASM Bytecode Malware Analyzer for Minecraft Plugins

**Detect backdoors, RATs, obfuscated payloads, and supply-chain attacks in plugin JARs**

[![Java](https://img.shields.io/badge/Java-17-orange)](#)
[![ASM](https://img.shields.io/badge/ASM-9.7-blue)](#)
[![License](https://img.shields.io/badge/License-MIT-green)](#)

</div>

---

## 🔍 What Is CronosNeedle?

CronosNeedle is a production-grade CLI security tool that performs **deep multi-pass static analysis** on Minecraft plugin JAR files using the ASM bytecode framework. It detects:

- 🐴 **Remote Access Trojans** (RATs) and reverse shells
- 🪝 **Backdoors** hidden in event handlers and static initializers
- 🔐 **Encrypted/packed payloads** via entropy analysis
- 🎭 **Obfuscated malicious code** with string decryption routines
- 📦 **Supply-chain attacks** with fake Bukkit/NMS internal packages
- 💀 **Java deserialization gadget chains**
- 🤖 **Discord bot token stealers** and webhook exfiltration
- 🪙 **Crypto wallet address harvesters**
- 📡 **Data exfiltration** via HTTP, sockets, and UDP

---

## 🚀 Quick Start

```bash
# Build from source
mvn clean package

# Scan a single plugin
java -jar target/cronosneedle-2.0.jar scan EvilPlugin.jar

# Scan with verbose output
java -jar target/cronosneedle-2.0.jar scan EvilPlugin.jar --verbose

# Scan with JSON report
java -jar target/cronosneedle-2.0.jar scan EvilPlugin.jar --json

# Aggressive scanning (lowered thresholds)
java -jar target/cronosneedle-2.0.jar scan EvilPlugin.jar --strict

# Recursive directory scan
java -jar target/cronosneedle-2.0.jar scan plugins/ --recursive
```

---

## 📊 Example Output

```
[CRITICAL] studio.krud.evil.Loader
           ↳ Reason : Runtime.exec() call detected
           ↳ Chain  : onEnable() → startLoader() → run() → Runtime.exec()

[HIGH] com.evil.a
           ↳ Reason : Static initializer contains network/exec call — auto-runs on class load

[MEDIUM] com.evil.b
           ↳ Reason : Single/double character class name detected: b

╔══════════════════════════════════════════════╗
║     ⚡ CronosNeedle v2.0  by Krud Studio      ║
╠══════════════════════════════════════════════╣
║  File      : EvilPlugin.jar                  ║
║  Classes   : 94 scanned                      ║
║  Strings   : 2,341 harvested                 ║
║  Passes    : 5 completed                     ║
╠══════════════════════════════════════════════╣
║  CRITICAL : 3   HIGH : 2   MED : 5   LOW : 8 ║
╠══════════════════════════════════════════════╣
║  VERDICT  : ⛔ MALICIOUS — DO NOT LOAD        ║
╚══════════════════════════════════════════════╝
```

---

## 🧠 Analysis Pipeline

CronosNeedle runs **5 sequential analysis passes**, each building on shared context from previous passes:

### Pass 1 — String Harvester 🔤
Extracts ALL `LDC` string constants and flags:
- Raw IP URLs & known exfiltration hosts (Pastebin, Discord webhooks, etc.)
- Base64-encoded payloads (>80 chars)
- Hex blobs (possible shellcode or encryption keys)
- Shell command keywords (`cmd.exe /c`, `/bin/bash`, `wget`, `curl`)
- Discord bot tokens & crypto wallet addresses
- Sensitive server file paths (`ops.json`, `server.properties`, etc.)
- Fake internal package strings

### Pass 2 — Opcode Analyzer 🧬
Bytecode-level instruction analysis across 4 severity tiers:

| Severity | Detections |
|----------|-----------|
| **CRITICAL** | `Runtime.exec`, `ProcessBuilder`, `ClassLoader.defineClass`, `URLClassLoader`, `ServerSocket`, `Unsafe`, reflection bypass, static initializer exploits, encrypted payload loaders (Cipher + defineClass) |
| **HIGH** | HTTP POST, env/property exfil, deserialization (`readObject`), `ScriptEngine.eval`, `MethodHandles`, shutdown hook exfil, ProcessBuilder env manipulation, ZipOutputStream archives |
| **MEDIUM** | Outbound sockets, UDP exfil, file deletion, sleep in handlers, Base64 decode + file write, static initializer config exfil |
| **LOW** | Excessive empty catch blocks, suspicious short method names, classes with no Bukkit API but heavy I/O |

### Pass 3 — Call Graph Tracer 🕸️
Builds a full inter-class call graph and performs **BFS traversal** (depth 8) from:
- `onEnable()`, `onLoad()`, `onDisable()`
- `<init>`, `<clinit>`
- All `@EventHandler` annotated methods

Traces execution paths to critical methods and produces **full call chain strings**:
```
onEnable() → startTask() → a.run() → Runtime.exec()
```

### Pass 4 — Obfuscation Detector 🎭
Detects deliberate code obfuscation:
- Single/double character class names
- Repeating character method names (`llll`, `OOOO`)
- Heavy byte manipulation without string constants (string decryption routines)
- String decryptor methods called from 5+ different classes
- Fake Bukkit/NMS internal packages
- High obfuscation ratio (>60% short-named methods)
- Excessive synthetic methods
- **Cross-reference escalation**: obfuscated classes with Pass 2 findings → CRITICAL

### Pass 5 — Entropy Analyzer 📈
Computes **Shannon entropy** of raw class file bytes:
- **>7.5** → CRITICAL: "Extremely high entropy — likely encrypted code blob"
- **>7.2** → HIGH: "High entropy — possible encrypted/packed payload"
- Normal Java class entropy: 5.5–6.8
- Whitelists trusted packages (Bukkit, Paper, Mojang, Gson, Guava, etc.)

---

## 🔧 CLI Reference

```
Usage:
  java -jar cronosneedle.jar scan <file.jar> [options]
  java -jar cronosneedle.jar scan <directory> --recursive

Options:
  --recursive, -r    Scan all .jar files in directory tree
  --verbose, -v      Show detailed analysis progress
  --json, -j         Generate JSON report (cronosneedle-report.json)
  --strict, -s       Lower detection thresholds for aggressive scanning

Exit codes:
  0 — ✅ Clean
  1 — ⚠ Suspicious / Low Risk
  2 — ⛔ Malicious
  3 — Error
```

---

## 📄 JSON Report

When run with `--json`, outputs `cronosneedle-report.json`:

```json
{
  "file": "EvilPlugin.jar",
  "verdict": "MALICIOUS",
  "classesScanned": 94,
  "stringsHarvested": 2341,
  "passesCompleted": 5,
  "findings": [
    {
      "severity": "CRITICAL",
      "class": "studio.krud.evil.Loader",
      "method": "run",
      "description": "Runtime.exec() call detected",
      "callChain": "onEnable() → startLoader() → run() → Runtime.exec()"
    }
  ]
}
```

---

## 🏗️ Build from Source

```bash
# Requirements: Java 17+, Maven 3.8+
mvn clean package

# Fat JAR with all dependencies bundled
ls -lh target/cronosneedle-2.0.jar
```

---

## 🛡️ Why This Matters

Minecraft plugin servers are prime targets for supply-chain attacks. Malicious plugins can:
- Steal server operator credentials and player data
- Install persistent backdoors that survive restarts
- Exfiltrate server configurations and world data
- Deploy cryptominers or join botnets
- Wipe server files or encrypt them for ransom

CronosNeedle catches these threats **before** they're loaded into your server — no runtime overhead, no agent required.

---

## 📁 Project Structure

```
cronosneedle/
├── pom.xml
└── src/main/java/studio/krud/cronosneedle/
    ├── Main.java
    ├── JarScanner.java
    ├── engine/
    │   ├── AnalysisContext.java        ← shared state across all passes
    │   ├── Pass1_StringHarvester.java
    │   ├── Pass2_OpcodeAnalyzer.java
    │   ├── Pass3_CallGraphTracer.java
    │   ├── Pass4_ObfuscationDetector.java
    │   └── Pass5_EntropyAnalyzer.java
    ├── model/
    │   ├── Finding.java                ← severity, class, method, chain
    │   └── ScanResult.java
    └── report/
        ├── TerminalReporter.java       ← ANSI colored terminal output
        └── JsonReporter.java           ← structured JSON report
```

---

<div align="center">

**Built with ❤️ by Krud Studio**

ASM 9.7 · Gson 2.10.1 · Java 17

</div>
