"""Tests for dependency injection-aware call resolution.

Tests that the TypeScript analyzer extracts constructor parameter types
and the dependency resolver uses them to resolve DI-injected service calls.

Requires Node.js and npm dependencies installed:
  cd parsers/javascript && npm install
"""
import json
import shutil
from pathlib import Path

from utilities.file_io import run_utf8

import pytest

PARSERS_JS_DIR = Path(__file__).parent.parent / "parsers" / "javascript"
NODE_MODULES = PARSERS_JS_DIR / "node_modules"

pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)


def run_node(script_name, *args):
    """Run a Node.js script from the JS parsers directory."""
    cmd = ["node", str(PARSERS_JS_DIR / script_name)] + list(args)
    return run_utf8(cmd, capture_output=True, text=True, timeout=30)


# -- Fixture: NestJS-style DI codebase --

RESOLVER_TS = """\
import { Injectable } from '@nestjs/common';
import { CallService } from './call.service';
import { AuthService } from './auth.service';

@Injectable()
export class CallResolver {
    constructor(
        private callService: CallService,
        private authService: AuthService,
    ) {}

    async getCall(id: string) {
        return await this.callService.getById(id);
    }

    async deleteCall(id: string) {
        return await this.callService.remove(id);
    }
}
"""

SERVICE_TS = """\
import { Injectable } from '@nestjs/common';

@Injectable()
export class CallService {
    async getById(id: string) {
        const call = await this.repository.findOne(id);
        await this.authService.can('read', call);
        return call;
    }

    async remove(id: string) {
        return await this.repository.delete(id);
    }
}
"""

AUTH_SERVICE_TS = """\
import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
    async can(action: string, resource: any) {
        // authorization check
        return true;
    }
}
"""

# Versioned implementation (interface CallService, impl CallServiceV2)
VERSIONED_SERVICE_TS = """\
import { Injectable } from '@nestjs/common';

@Injectable()
export class CallServiceV2 {
    async getById(id: string) {
        return { id };
    }

    async remove(id: string) {
        return true;
    }
}
"""


@pytest.fixture
def nestjs_repo(tmp_path):
    """Create a minimal NestJS-style repo with DI patterns."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "call.resolver.ts").write_text(RESOLVER_TS)
    (src / "call.service.ts").write_text(SERVICE_TS)
    (src / "auth.service.ts").write_text(AUTH_SERVICE_TS)
    return tmp_path


@pytest.fixture
def nestjs_repo_versioned(tmp_path):
    """Create a repo where the DI type doesn't exactly match the class name."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "call.resolver.ts").write_text(RESOLVER_TS)
    (src / "call.service.ts").write_text(VERSIONED_SERVICE_TS)
    return tmp_path


def analyze_and_resolve(repo_path, files):
    """Run analyzer + resolver on given files and return resolved data."""
    analyzer_out = repo_path / "analyzer_output.json"
    resolved_out = repo_path / "resolved.json"

    file_paths = [str(f) for f in files]
    result = run_node(
        "typescript_analyzer.js", str(repo_path),
        *file_paths,
        "--output", str(analyzer_out),
    )
    assert result.returncode == 0, f"Analyzer failed: {result.stderr}"

    result = run_node(
        "dependency_resolver.js", str(analyzer_out),
        "--output", str(resolved_out),
    )
    assert result.returncode == 0, f"Resolver failed: {result.stderr}"

    return json.loads(resolved_out.read_text())


class TestConstructorDepsExtraction:
    """Test that the analyzer extracts constructorDeps from class constructors."""

    def test_extracts_constructor_deps(self, nestjs_repo):
        analyzer_out = nestjs_repo / "analyzer_output.json"
        result = run_node(
            "typescript_analyzer.js", str(nestjs_repo),
            "src/call.resolver.ts",
            "--output", str(analyzer_out),
        )
        assert result.returncode == 0

        data = json.loads(analyzer_out.read_text())
        functions = data["functions"]

        # Find a CallResolver method
        resolver_methods = {
            fid: f for fid, f in functions.items()
            if "CallResolver" in fid
        }
        assert len(resolver_methods) > 0, "No CallResolver methods found"

        # Each method should have constructorDeps
        for fid, func in resolver_methods.items():
            assert "constructorDeps" in func, f"{fid} missing constructorDeps"
            deps = func["constructorDeps"]
            assert deps.get("callService") == "CallService"
            assert deps.get("authService") == "AuthService"

    def test_skips_primitive_types(self, tmp_path):
        """Constructor params with primitive types should not be included."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "example.ts").write_text("""\
export class Example {
    constructor(
        private name: string,
        private count: number,
        private service: MyService,
    ) {}

    doWork() {
        return this.service.run();
    }
}
""")
        analyzer_out = tmp_path / "analyzer_output.json"
        result = run_node(
            "typescript_analyzer.js", str(tmp_path),
            "src/example.ts",
            "--output", str(analyzer_out),
        )
        assert result.returncode == 0

        data = json.loads(analyzer_out.read_text())
        func = next(
            f for f in data["functions"].values()
            if f.get("className") == "Example"
        )
        deps = func.get("constructorDeps", {})
        # Only MyService should be captured (PascalCase), not string/number
        assert "service" in deps
        assert deps["service"] == "MyService"
        assert "name" not in deps
        assert "count" not in deps


class TestDIAwareCallResolution:
    """Test that the dependency resolver uses constructorDeps for DI resolution."""

    def test_resolves_exact_type_match(self, nestjs_repo):
        """this.callService.getById() resolves to CallService.getById."""
        data = analyze_and_resolve(nestjs_repo, [
            "src/call.resolver.ts",
            "src/call.service.ts",
        ])

        call_graph = data["callGraph"]

        # Find CallResolver.getCall's call graph
        resolver_calls = None
        for fid, calls in call_graph.items():
            if "CallResolver.getCall" in fid:
                resolver_calls = calls
                break

        assert resolver_calls is not None, "CallResolver.getCall not in call graph"
        assert any(
            "CallService.getById" in c for c in resolver_calls
        ), f"Expected CallService.getById in calls, got: {resolver_calls}"

    def test_resolves_versioned_implementation(self, nestjs_repo_versioned):
        """this.callService.getById() resolves to CallServiceV2.getById via prefix match."""
        data = analyze_and_resolve(nestjs_repo_versioned, [
            "src/call.resolver.ts",
            "src/call.service.ts",
        ])

        call_graph = data["callGraph"]
        resolver_calls = None
        for fid, calls in call_graph.items():
            if "CallResolver.getCall" in fid:
                resolver_calls = calls
                break

        assert resolver_calls is not None
        assert any(
            "CallServiceV2.getById" in c for c in resolver_calls
        ), f"Expected CallServiceV2.getById in calls, got: {resolver_calls}"

    def test_resolves_multiple_di_methods(self, nestjs_repo):
        """Both getById and remove should resolve to CallService methods."""
        data = analyze_and_resolve(nestjs_repo, [
            "src/call.resolver.ts",
            "src/call.service.ts",
        ])

        call_graph = data["callGraph"]

        # deleteCall should resolve to CallService.remove
        delete_calls = None
        for fid, calls in call_graph.items():
            if "CallResolver.deleteCall" in fid:
                delete_calls = calls
                break

        assert delete_calls is not None
        assert any(
            "CallService.remove" in c for c in delete_calls
        ), f"Expected CallService.remove in calls, got: {delete_calls}"

    def test_no_false_positives_without_di(self, tmp_path):
        """Methods without constructor deps should not spuriously resolve."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "plain.ts").write_text("""\
export class PlainService {
    doWork() {
        return this.unknownService.process();
    }
}
""")
        (src / "other.ts").write_text("""\
export class UnknownService {
    process() {
        return 42;
    }
}
""")
        data = analyze_and_resolve(tmp_path, [
            "src/plain.ts",
            "src/other.ts",
        ])

        call_graph = data["callGraph"]
        plain_calls = None
        for fid, calls in call_graph.items():
            if "PlainService.doWork" in fid:
                plain_calls = calls
                break

        # Without constructor deps, unknownService.process() should NOT resolve
        assert plain_calls is not None
        assert not any(
            "UnknownService.process" in c for c in plain_calls
        ), f"Should not resolve without DI metadata, got: {plain_calls}"
