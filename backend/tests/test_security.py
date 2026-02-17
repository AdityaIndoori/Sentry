"""
TDD tests for the SecurityGuard - the most critical component.
Tests path traversal, command injection, URL validation, and mode enforcement.
"""

import os
import pytest
from backend.shared.config import SecurityConfig, SentryMode
from backend.shared.security import SecurityGuard


class TestPathValidation:
    """Verify path traversal attacks are blocked."""

    def test_valid_path(self, security_guard, project_root):
        assert security_guard.validate_path("config/db.py") is True

    def test_blocks_parent_traversal(self, security_guard):
        assert security_guard.validate_path("../../etc/passwd") is False

    def test_blocks_absolute_escape(self, security_guard):
        assert security_guard.validate_path("/etc/passwd") is False

    def test_blocks_dot_dot_in_middle(self, security_guard):
        assert security_guard.validate_path("config/../../../etc/shadow") is False

    def test_allows_nested_valid_path(self, security_guard):
        assert security_guard.validate_path("config/db.py") is True

    def test_empty_path(self, security_guard):
        # Should resolve to project root itself - valid
        assert security_guard.validate_path(".") is True


class TestCommandValidation:
    """Verify command whitelist enforcement."""

    def test_allowed_command(self, security_guard):
        assert security_guard.validate_command("ps aux") is True

    def test_allowed_command_with_args(self, security_guard):
        assert security_guard.validate_command("tail -f /var/log/syslog") is True

    def test_blocked_dangerous_command(self, security_guard):
        assert security_guard.validate_command("rm -rf /") is False

    def test_blocked_shell_injection(self, security_guard):
        assert security_guard.validate_command("cat file; rm -rf /") is False

    def test_blocked_python_exec(self, security_guard):
        assert security_guard.validate_command("python -c 'import os'") is False

    def test_empty_command(self, security_guard):
        assert security_guard.validate_command("") is False


class TestURLValidation:
    """Verify URL domain allow-list."""

    def test_allowed_domain(self, security_guard):
        assert security_guard.validate_url("https://docs.python.org/3/") is True

    def test_allowed_subdomain(self, security_guard):
        assert security_guard.validate_url("https://www.docs.python.org/") is True

    def test_blocked_domain(self, security_guard):
        assert security_guard.validate_url("https://evil.com/malware") is False

    def test_blocked_ip_address(self, security_guard):
        assert security_guard.validate_url("http://192.168.1.1/admin") is False

    def test_invalid_url(self, security_guard):
        assert security_guard.validate_url("not-a-url") is False


class TestModeEnforcement:
    """Verify AUDIT/ACTIVE/DISABLED mode behavior."""

    def test_audit_mode_default(self, security_guard):
        assert security_guard.is_audit_mode() is True
        assert security_guard.is_active_mode() is False

    def test_active_mode(self, active_security_guard):
        assert active_security_guard.is_active_mode() is True
        assert active_security_guard.is_audit_mode() is False

    def test_stop_file_overrides_active(self, active_security_guard, project_root):
        # Create STOP_SENTRY file
        stop_path = os.path.join(project_root, "STOP_SENTRY")
        with open(stop_path, "w") as f:
            f.write("EMERGENCY STOP")
        assert active_security_guard.is_stopped() is True
        assert active_security_guard.is_audit_mode() is True
        assert active_security_guard.is_active_mode() is False
        os.unlink(stop_path)

    def test_disabled_mode(self, project_root):
        config = SecurityConfig(
            mode=SentryMode.DISABLED,
            project_root=project_root,
        )
        guard = SecurityGuard(config)
        assert guard.is_active_mode() is False
        assert guard.is_audit_mode() is False


class TestInputSanitization:
    """Verify dangerous input is stripped."""

    def test_strips_semicolon(self, security_guard):
        assert ";" not in security_guard.sanitize_input("hello; rm -rf /")

    def test_strips_pipe(self, security_guard):
        assert "|" not in security_guard.sanitize_input("cat file | grep pass")

    def test_strips_backtick(self, security_guard):
        assert "`" not in security_guard.sanitize_input("echo `whoami`")

    def test_strips_subshell(self, security_guard):
        assert "$(" not in security_guard.sanitize_input("echo $(id)")

    def test_clean_input_unchanged(self, security_guard):
        assert security_guard.sanitize_input("hello world") == "hello world"
