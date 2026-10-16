package dodns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnsurePlaceholder(t *testing.T) {
	var records []Record
	creates := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			if r.URL.Path != "/v2/domains/d.test/records" || r.URL.Query().Get("name") != "lbl.d.test" || r.URL.Query().Get("type") != "TXT" {
				t.Errorf("unexpected list query %s", r.URL)
			}
			json.NewEncoder(w).Encode(map[string]any{"domain_records": records})
		case http.MethodPost:
			var rec Record
			json.NewDecoder(r.Body).Decode(&rec)
			creates++
			rec.ID = creates
			records = append(records, rec)
			json.NewEncoder(w).Encode(map[string]any{"domain_record": rec})
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}
	ctx := context.Background()

	// An unrelated TXT (e.g. a challenge in progress) doesn't count.
	records = []Record{{ID: 99, Type: "TXT", Name: "lbl", Data: "challenge"}}
	made, err := c.EnsurePlaceholder(ctx, "d.test", "lbl", 30)
	if err != nil || !made || creates != 1 || records[1].Data != PlaceholderValue || records[1].TTL != 30 {
		t.Fatalf("made=%v err=%v records=%+v", made, err, records)
	}
	// Present (DigitalOcean may return TXT data quoted): nothing to do.
	records[1].Data = `"` + PlaceholderValue + `"`
	if made, err := c.EnsurePlaceholder(ctx, "d.test", "lbl", 30); err != nil || made || creates != 1 {
		t.Fatalf("second call: made=%v err=%v", made, err)
	}
	c.Token = "bad"
	if _, err := c.EnsurePlaceholder(ctx, "d.test", "lbl", 30); err == nil {
		t.Fatal("expected API error")
	}
}
