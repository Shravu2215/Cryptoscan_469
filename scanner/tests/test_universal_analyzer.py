import pytest
from scanner.universal_analyzer import UniversalAnalyzer
from scanner.models import QuantumRisk, Severity

def test_universal_analyzer_java():
    analyzer = UniversalAnalyzer()
    java_code = """
    package com.example.crypto;
    import java.security.MessageDigest;
    import javax.crypto.Cipher;

    public class App {
        public void test() throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5");
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        }
    }
    """
    findings = analyzer.analyze("App.java", java_code)
    rule_ids = [f.rule_id for f in findings]
    assert "java-md5-digest" in rule_ids
    assert "java-des-cipher" in rule_ids

def test_universal_analyzer_go():
    analyzer = UniversalAnalyzer()
    go_code = """
    package main
    import (
        "crypto/md5"
        "crypto/des"
    )

    func main() {
        h := md5.New()
        c, _ := des.NewCipher([]byte("12345678"))
    }
    """
    findings = analyzer.analyze("main.go", go_code)
    rule_ids = [f.rule_id for f in findings]
    assert "go-md5-hash" in rule_ids
    assert "go-des-cipher" in rule_ids

def test_universal_analyzer_csharp():
    analyzer = UniversalAnalyzer()
    cs_code = """
    using System;
    using System.Security.Cryptography;

    class Program {
        static void Main() {
            var md5 = MD5.Create();
            var des = new DESCryptoServiceProvider();
        }
    }
    """
    findings = analyzer.analyze("Program.cs", cs_code)
    rule_ids = [f.rule_id for f in findings]
    assert "csharp-md5-crypto" in rule_ids
    assert "csharp-des-cipher" in rule_ids

def test_universal_analyzer_coverage():
    analyzer = UniversalAnalyzer()
    analyzer.analyze("Test.java", "class Test {}")
    analyzer.analyze("main.go", "package main")
    stats = analyzer.get_coverage_stats()
    assert stats["scanned"] == 2
    assert "java" in stats["by_language"]
    assert "go" in stats["by_language"]
