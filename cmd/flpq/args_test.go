package main

import "testing"

// A mistyped address must be rejected, never mapped to another address.
func TestParseAddrStrict(t *testing.T) {
	for _, s := range []string{"0x12", "0xZZ00000000000000000000000000000000000000", "0x000000000000000000000000000000000000000012", ""} {
		if _, err := parseAddr(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if _, err := parseAddr("0x998F0BdB961405efe14045eF8b6F3f09d4aB6570"); err != nil {
		t.Error(err)
	}
	if _, _, err := extractFrom([]string{"send", "--from", "0x12"}); err == nil {
		t.Error("bad --from accepted")
	}
}
