package python

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVenvPython_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("test only runs on Windows")
	}

	vp := venvPython()
	expected := filepath.Join(os.Getenv("USERPROFILE"), ".openant", "venv", "Scripts", "python.exe")
	if vp != expected {
		t.Errorf("venvPython() = %q, want %q", vp, expected)
	}

	if !filepath.IsAbs(vp) {
		t.Errorf("venvPython() should return absolute path, got %q", vp)
	}
}

func TestVenvPython_Unix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix-like systems")
	}

	vp := venvPython()
	if !filepath.IsAbs(vp) {
		t.Errorf("venvPython() should return absolute path, got %q", vp)
	}

	if !strings.HasSuffix(vp, filepath.Join("bin", "python")) {
		t.Errorf("venvPython() on Unix should end with bin/python, got %q", vp)
	}
}

func TestVenvDir_ReturnsAbsolutePath(t *testing.T) {
	vd := venvDir()
	if !filepath.IsAbs(vd) {
		t.Errorf("venvDir() should return absolute path, got %q", vd)
	}
}
