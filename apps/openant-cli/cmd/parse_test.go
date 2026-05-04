package cmd

import "testing"

func TestParseLevelFlagDefaultIsReachable(t *testing.T) {
	flag := parseCmd.Flag("level")
	if flag == nil {
		t.Fatal("parseCmd has no --level flag")
	}
	if got, want := flag.DefValue, "reachable"; got != want {
		t.Errorf("--level default = %q, want %q", got, want)
	}
}
