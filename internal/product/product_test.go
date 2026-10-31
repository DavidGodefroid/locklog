package product

import "testing"

func TestProduct(t *testing.T) {
	if err := P.Validate(); err != nil {
		t.Fatal(err)
	}
	if P.ProjectDir() != ".locklog" || P.Env("NETWORK") != "LOCKLOG_NETWORK" {
		t.Errorf("names: %q %q", P.ProjectDir(), P.Env("NETWORK"))
	}
	// 10040 is lockhub's; locklog's ids are 10050-10052.
	if ClientsGID != 10050 || ConsoleUID != 10051 || AgentUID != 10052 {
		t.Error("account ids changed")
	}
}
