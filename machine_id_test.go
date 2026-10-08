package latte

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/denisbrodbeck/machineid"
)

func TestProtectMachineID_Vectors(t *testing.T) {
	data, err := os.ReadFile("testdata/machine_id.json")
	if err != nil {
		t.Fatalf("read vectors (is the testdata submodule populated?): %v", err)
	}
	var file struct {
		Cases []struct {
			RawMachineID    string `json:"raw_machine_id"`
			AppID           string `json:"app_id"`
			ExpectMachineID string `json:"expect_machine_id"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no machine ID cases")
	}
	for _, c := range file.Cases {
		if got := protectMachineID(c.RawMachineID, c.AppID); got != c.ExpectMachineID {
			t.Errorf("protectMachineID(%q, %q) = %s, want %s", c.RawMachineID, c.AppID, got, c.ExpectMachineID)
		}
	}
}

// The OS path must hash exactly as machineid.ProtectedID does, so installs
// activated before MachineID existed keep their identity.
func TestProtectMachineID_MatchesProtectedID(t *testing.T) {
	const appID = "pk_test_abc123"
	raw, err := machineid.ID()
	if err != nil {
		t.Skipf("no OS machine ID here: %v", err)
	}
	want, err := machineid.ProtectedID("licenselatte_" + appID)
	if err != nil {
		t.Fatal(err)
	}
	if got := protectMachineID(raw, appID); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
