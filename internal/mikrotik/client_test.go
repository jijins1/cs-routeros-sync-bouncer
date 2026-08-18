package mikrotik

import "testing"

func TestEntryManaged(t *testing.T) {
	tests := []struct {
		name    string
		comment string
		want    bool
	}{
		{name: "exact marker", comment: ManagedComment, want: true},
		{name: "marker with detail", comment: ManagedComment + ";crowdsec", want: true},

		// Anything else belongs to the operator and is off-limits.
		{name: "empty comment", comment: "", want: false},
		{name: "operator comment", comment: "office VPN", want: false},

		// A comment that merely starts with the same letters is not ours; the
		// separator matters, or we would delete somebody else's entries.
		{name: "similar prefix", comment: ManagedComment + "-other", want: false},
		{name: "marker not at start", comment: "not " + ManagedComment, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := Entry{Comment: tt.comment}
			if got := e.Managed(); got != tt.want {
				t.Errorf("Entry{Comment: %q}.Managed() = %v, want %v", tt.comment, got, tt.want)
			}
		})
	}
}

func TestAttr(t *testing.T) {
	got, err := attr("address", "1.2.3.4")
	if err != nil {
		t.Fatalf("attr: %v", err)
	}
	if want := "=address=1.2.3.4"; got != want {
		t.Errorf("attr = %q, want %q", got, want)
	}
}

// A value carrying framing characters would be reinterpreted by the router,
// so it is refused rather than sent.
func TestAttrRejectsControlCharacters(t *testing.T) {
	for _, value := range []string{"1.2.3.4\n", "1.2.3.4\r", "1.2.3.4\x00", "a\nb"} {
		if _, err := attr("address", value); err == nil {
			t.Errorf("attr accepted %q", value)
		}
	}
}

func TestJoinIDs(t *testing.T) {
	tests := []struct {
		in   []string
		want string
	}{
		{in: []string{"*1"}, want: "*1"},
		{in: []string{"*1", "*2", "*3"}, want: "*1,*2,*3"},
	}
	for _, tt := range tests {
		if got := joinIDs(tt.in); got != tt.want {
			t.Errorf("joinIDs(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
