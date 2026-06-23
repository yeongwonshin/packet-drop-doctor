package doctor

import "testing"

func TestExplainFirewall(t *testing.T) {
	exp := Explain(Event{Reason: 7})
	if exp.Domain != DomainFirewall {
		t.Fatalf("expected firewall, got %s", exp.Domain)
	}
}

func TestReasonFallback(t *testing.T) {
	got := ReasonName(9999)
	if got != "SKB_DROP_REASON_9999" {
		t.Fatalf("unexpected fallback: %s", got)
	}
}
