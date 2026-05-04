package cmd

import (
	"strings"
	"testing"
)

func TestParseLevelFlagDefaultIsReachable(t *testing.T) {
	flag := parseCmd.Flag("level")
	if flag == nil {
		t.Fatal("parseCmd has no --level flag")
	}
	if got, want := flag.DefValue, "reachable"; got != want {
		t.Errorf("--level default = %q, want %q", got, want)
	}
}

func TestParseLevelFlagUsageMentionsChoices(t *testing.T) {
	flag := parseCmd.Flag("level")
	if flag == nil {
		t.Fatal("parseCmd has no --level flag")
	}
	for _, choice := range []string{"all", "reachable", "codeql", "exploitable"} {
		if !strings.Contains(flag.Usage, choice) {
			t.Errorf("--level usage missing %q: %q", choice, flag.Usage)
		}
	}
}

func TestBuildParsePyArgsLevelForwarding(t *testing.T) {
	tests := []struct {
		name      string
		level     string
		wantLevel bool // true if --level should appear in argv
	}{
		{"default reachable is omitted", "reachable", false},
		{"all is forwarded", "all", true},
		{"codeql is forwarded", "codeql", true},
		{"exploitable is forwarded", "exploitable", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := buildParsePyArgs("/repo", "/out", "", "auto", tc.level, "")
			gotLevel, gotValue := findFlag(args, "--level")
			if gotLevel != tc.wantLevel {
				t.Errorf("--level present = %v, want %v (argv=%v)", gotLevel, tc.wantLevel, args)
			}
			if tc.wantLevel && gotValue != tc.level {
				t.Errorf("--level value = %q, want %q (argv=%v)", gotValue, tc.level, args)
			}
		})
	}
}

func TestBuildParsePyArgsBaseline(t *testing.T) {
	args := buildParsePyArgs("/repo", "/out", "org-repo-abc1234", "python", "exploitable", "/tmp/manifest.json")
	want := []string{
		"parse", "/repo",
		"--output", "/out",
		"--name", "org-repo-abc1234",
		"--language", "python",
		"--level", "exploitable",
		"--diff-manifest", "/tmp/manifest.json",
	}
	if len(args) != len(want) {
		t.Fatalf("argv = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q (full=%v)", i, args[i], want[i], args)
		}
	}
}

// findFlag returns whether name is present in argv, and its following value
// (or "" if it has no value).
func findFlag(argv []string, name string) (bool, string) {
	for i, a := range argv {
		if a == name {
			if i+1 < len(argv) {
				return true, argv[i+1]
			}
			return true, ""
		}
	}
	return false, ""
}
