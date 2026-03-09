package securityevent

import "testing"

func TestNewSecurityEventClient_returnsNonNil(t *testing.T) {
	c := NewSecurityEventClient(nil)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}
