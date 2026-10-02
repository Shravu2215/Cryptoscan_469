"""
test_language_detector.py - Unit tests for scanner/language_detector.py.
"""
import os
import sys
import pytest

_scanner_dir = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
_parent_dir = os.path.normpath(os.path.join(_scanner_dir, ".."))
for p in (_parent_dir, _scanner_dir):
    if p not in sys.path:
        sys.path.insert(0, p)

from scanner.language_detector import detect_language


def dl(path, source=None):
    return detect_language(path, source)


class TestExtensions:
    def test_python(self):         assert dl("app.py") == "Python"
    def test_python_pyi(self):     assert dl("stubs.pyi") == "Python"
    def test_javascript(self):     assert dl("index.js") == "JavaScript"
    def test_javascript_mjs(self): assert dl("mod.mjs") == "JavaScript"
    def test_jsx(self):            assert dl("comp.jsx") == "JSX"
    def test_typescript(self):     assert dl("app.ts") == "TypeScript"
    def test_tsx(self):            assert dl("comp.tsx") == "TSX"
    def test_java(self):           assert dl("Main.java") == "Java"
    def test_kotlin(self):         assert dl("App.kt") == "Kotlin"
    def test_kotlin_kts(self):     assert dl("build.kts") == "Kotlin"
    def test_scala(self):          assert dl("Main.scala") == "Scala"
    def test_groovy(self):         assert dl("build.groovy") == "Groovy"
    def test_go(self):             assert dl("main.go") == "Go"
    def test_rust(self):           assert dl("lib.rs") == "Rust"
    def test_c(self):              assert dl("util.c") == "C"
    def test_c_header(self):       assert dl("util.h") == "C"
    def test_cpp(self):            assert dl("main.cpp") == "C++"
    def test_cpp_cc(self):         assert dl("main.cc") == "C++"
    def test_csharp(self):         assert dl("Program.cs") == "C#"
    def test_swift(self):          assert dl("App.swift") == "Swift"
    def test_dart(self):           assert dl("main.dart") == "Dart"
    def test_php(self):            assert dl("index.php") == "PHP"
    def test_ruby(self):           assert dl("app.rb") == "Ruby"
    def test_perl(self):           assert dl("script.pl") == "Perl"
    def test_lua(self):            assert dl("main.lua") == "Lua"
    def test_r(self):              assert dl("analysis.R") == "R"
    def test_r_lower(self):        assert dl("analysis.r") == "R"
    def test_julia(self):          assert dl("algo.jl") == "Julia"
    def test_haskell(self):        assert dl("Main.hs") == "Haskell"
    def test_elixir(self):         assert dl("app.ex") == "Elixir"
    def test_erlang(self):         assert dl("server.erl") == "Erlang"
    def test_clojure(self):        assert dl("core.clj") == "Clojure"
    def test_fsharp(self):         assert dl("Lib.fs") == "F#"
    def test_ocaml(self):          assert dl("parser.ml") == "OCaml"
    def test_visualbasic(self):    assert dl("Module.vb") == "Visual Basic"
    def test_fortran(self):        assert dl("num.f90") == "Fortran"
    def test_cobol(self):          assert dl("main.cob") == "COBOL"
    def test_pascal(self):         assert dl("unit.pas") == "Pascal/Delphi"
    def test_assembly(self):       assert dl("boot.asm") == "Assembly"
    def test_solidity(self):       assert dl("Token.sol") == "Solidity"
    def test_vyper(self):          assert dl("Vault.vy") == "Vyper"
    def test_zig(self):            assert dl("main.zig") == "Zig"
    def test_nim(self):            assert dl("app.nim") == "Nim"
    def test_crystal(self):        assert dl("app.cr") == "Crystal"
    def test_powershell(self):     assert dl("deploy.ps1") == "PowerShell"
    def test_bash(self):           assert dl("deploy.sh") == "Bash/Shell"
    def test_zsh(self):            assert dl("setup.zsh") == "Zsh"
    def test_batch(self):          assert dl("build.bat") == "Batch"
    def test_sql(self):            assert dl("query.sql") == "SQL"
    def test_plsql(self):          assert dl("proc.plsql") == "PL/SQL"
    def test_html(self):           assert dl("page.html") == "HTML"
    def test_css(self):            assert dl("style.css") == "CSS"
    def test_scss(self):           assert dl("style.scss") == "SCSS"
    def test_sass(self):           assert dl("style.sass") == "Sass"
    def test_less(self):           assert dl("style.less") == "Less"
    def test_vue(self):            assert dl("App.vue") == "Vue"
    def test_svelte(self):         assert dl("App.svelte") == "Svelte"
    def test_xml(self):            assert dl("config.xml") == "XML"
    def test_markdown(self):       assert dl("README.md") == "Markdown"
    def test_json(self):           assert dl("data.json") == "JSON"
    def test_yaml(self):           assert dl("config.yaml") == "YAML"
    def test_yml(self):            assert dl("config.yml") == "YAML"
    def test_toml(self):           assert dl("config.toml") in ("Cargo.toml", "TOML")
    def test_ini(self):            assert dl("settings.ini") == "INI"
    def test_properties(self):     assert dl("app.properties") == "Properties"
    def test_dotenv_ext(self):     assert dl("secrets.env") == "Dotenv"
    def test_terraform(self):      assert dl("main.tf") == "Terraform/HCL"
    def test_protobuf(self):       assert dl("service.proto") == "Protobuf"
    def test_graphql(self):        assert dl("schema.graphql") == "GraphQL"
    def test_gradle_ext(self):     assert dl("library.gradle") == "Gradle"
    def test_makefile_mk(self):    assert dl("rules.mk") == "Makefile"
    def test_certificate_crt(self):  assert dl("server.crt") == "Certificate"
    def test_certificate_pem(self):  assert dl("ca.pem") == "Certificate"
    def test_certificate_cer(self):  assert dl("cert.cer") == "Certificate"
    def test_certificate_der(self):  assert dl("cert.der") == "Certificate"
    def test_private_key(self):      assert dl("private.key") == "Private key"
    def test_pkcs12_p12(self):       assert dl("keystore.p12") == "PKCS#12"
    def test_pkcs12_pfx(self):       assert dl("keystore.pfx") == "PKCS#12"
    def test_jks(self):              assert dl("keystore.jks") == "Java Keystore"
    def test_csr(self):              assert dl("request.csr") == "CSR"
    def test_ssh_pub(self):          assert dl("id_rsa.pub") == "SSH key"
    def test_csproj(self):           assert dl("App.csproj") == "C# project"


class TestExactFilenames:
    def test_dockerfile(self):           assert dl("Dockerfile") == "Dockerfile"
    def test_dockerfile_lowercase(self): assert dl("dockerfile") == "Dockerfile"
    def test_dockerfile_dev(self):       assert dl("Dockerfile.dev") == "Dockerfile"
    def test_makefile(self):             assert dl("Makefile") == "Makefile"
    def test_gnumakefile(self):          assert dl("GNUmakefile") == "Makefile"
    def test_cmakelists(self):           assert dl("CMakeLists.txt") == "CMake"
    def test_dotenv(self):               assert dl(".env") == "Dotenv"
    def test_dotenv_local(self):         assert dl(".env.local") == "Dotenv"
    def test_dotenv_production(self):    assert dl(".env.production") == "Dotenv"
    def test_nginx_conf(self):           assert dl("nginx.conf") == "Nginx config"
    def test_apache_conf(self):          assert dl("httpd.conf") == "Apache config"
    def test_openssl_cnf(self):          assert dl("openssl.cnf") == "OpenSSL config"
    def test_docker_compose_yml(self):   assert dl("docker-compose.yml") == "Docker Compose"
    def test_docker_compose_yaml(self):  assert dl("docker-compose.yaml") == "Docker Compose"
    def test_compose_yml(self):          assert dl("compose.yml") == "Docker Compose"
    def test_pipfile(self):              assert dl("Pipfile") == "Pipfile"
    def test_pyproject_toml(self):       assert dl("pyproject.toml") == "pyproject.toml"
    def test_requirements_txt(self):     assert dl("requirements.txt") == "pip requirements"
    def test_go_mod(self):               assert dl("go.mod") == "Go module"
    def test_cargo_toml(self):           assert dl("Cargo.toml") == "Cargo.toml"
    def test_gemfile(self):              assert dl("Gemfile") == "Gemfile"
    def test_composer_json(self):        assert dl("composer.json") == "composer.json"
    def test_package_json(self):         assert dl("package.json") == "Node (package.json)"
    def test_package_lock_json(self):    assert dl("package-lock.json") == "Node (package.json)"
    def test_pom_xml(self):              assert dl("pom.xml") == "Maven POM"
    def test_build_gradle(self):         assert dl("build.gradle") == "Gradle"
    def test_jenkinsfile(self):          assert dl("Jenkinsfile") == "Jenkinsfile"
    def test_authorized_keys(self):      assert dl("authorized_keys") == "SSH key"


class TestPrefixPatterns:
    def test_dockerfile_prefix(self):       assert dl("Dockerfile.custom") == "Dockerfile"
    def test_requirements_prefix(self):     assert dl("requirements-dev.txt") == "pip requirements"
    def test_dotenv_prefix(self):           assert dl(".env.test") == "Dotenv"
    def test_dotenv_prefix_staging(self):   assert dl(".env.staging") == "Dotenv"


class TestPathPatterns:
    def test_github_actions_workflow(self):
        assert dl(".github/workflows/ci.yml") == "GitHub Actions"
    def test_github_actions_any_yml(self):
        assert dl("repo/.github/workflows/deploy.yml") == "GitHub Actions"
    def test_gitlab_ci(self):
        assert dl(".gitlab-ci.yml") == "GitLab CI"
    def test_ansible_playbook(self):
        assert dl("ansible/playbooks/site.yml") == "Ansible"
    def test_kubernetes_k8s(self):
        assert dl("k8s/deployment.yaml") == "Kubernetes manifest"
    def test_kubernetes_dir(self):
        assert dl("kubernetes/service.yml") == "Kubernetes manifest"
    def test_helm_chart(self):
        assert dl("helm/values.yaml") == "Helm"


class TestShebang:
    def test_python3_shebang(self):
        assert dl("script", "#!/usr/bin/env python3\nprint('hi')") == "Python"
    def test_python_shebang(self):
        assert dl("script", "#!/usr/bin/python\nprint('hi')") == "Python"
    def test_bash_shebang(self):
        assert dl("script", "#!/bin/bash\necho hello") == "Bash/Shell"
    def test_sh_shebang(self):
        assert dl("script", "#!/bin/sh\necho hello") == "Bash/Shell"
    def test_node_shebang(self):
        assert dl("script", "#!/usr/bin/env node\nconsole.log('hi')") == "JavaScript"
    def test_ruby_shebang(self):
        assert dl("script", "#!/usr/bin/env ruby\nputs 'hi'") == "Ruby"
    def test_perl_shebang(self):
        assert dl("script", "#!/usr/bin/perl\nprint 'hi'") == "Perl"
    def test_powershell_shebang(self):
        assert dl("script", "#!/usr/bin/env pwsh\nWrite-Host 'hi'") == "PowerShell"


class TestContentHeuristics:
    def test_pem_cert_heuristic(self):
        pem = "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgI..."
        assert dl("somefile", pem) == "Certificate"
    def test_pem_private_key_heuristic(self):
        key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
        assert dl("somefile", key) == "Private key"
    def test_openssh_key_heuristic(self):
        key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC..."
        assert dl("somefile", key) == "SSH key"
    def test_dockerfile_heuristic(self):
        content = "FROM ubuntu:22.04\nRUN apt-get update\n"
        assert dl("somefile", content) == "Dockerfile"


class TestFallback:
    def test_unknown_extension(self):
        assert dl("binary.xyz42") == "Unknown"
    def test_no_extension_no_source(self):
        assert dl("somefile") == "Unknown"
    def test_empty_content_no_match(self):
        assert dl("somefile", "random content that matches nothing") == "Unknown"
    def test_never_empty_or_none(self):
        result = dl("", None)
        assert result is not None
        assert result != ""


class TestDeterminism:
    @pytest.mark.parametrize("path,source", [
        ("app.py", None),
        ("Dockerfile", None),
        (".env", None),
        (".github/workflows/ci.yml", None),
        ("somefile", "#!/usr/bin/env python3\ncode"),
        ("cert.pem", "-----BEGIN CERTIFICATE-----\ndata"),
        ("unknown.xyz", None),
    ])
    def test_deterministic(self, path, source):
        results = [detect_language(path, source) for _ in range(5)]
        assert len(set(results)) == 1, f"Non-deterministic for {path!r}: {results}"


class TestFixtureRegression:
    """Mirrors language labels from pqc-test-fixture.zip file paths."""
    def test_env_file(self):         assert dl(".env") == "Dotenv"
    def test_env_prefixed(self):     assert dl(".env.production") == "Dotenv"
    def test_js_file(self):          assert dl("src/crypto/cipherModes.js") == "JavaScript"
    def test_python_file(self):      assert dl("auth/crypto_utils.py") == "Python"
    def test_requirements(self):     assert dl("requirements.txt") == "pip requirements"
    def test_package_json(self):     assert dl("package.json") == "Node (package.json)"
    def test_certificate_crt(self):  assert dl("certs/server.crt") == "Certificate"
    def test_private_key(self):      assert dl("certs/server.key") == "Private key"
    def test_nginx_conf(self):       assert dl("nginx.conf") == "Nginx config"
    def test_docker_compose(self):   assert dl("docker-compose.yml") == "Docker Compose"
    def test_dockerfile_fixture(self): assert dl("Dockerfile") == "Dockerfile"
    def test_github_actions_ci(self):  assert dl(".github/workflows/ci.yml") == "GitHub Actions"
