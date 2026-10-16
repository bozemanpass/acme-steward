// Package dodns is a minimal DigitalOcean DNS API client, used to keep a
// permanent placeholder TXT record at each delegate label.
//
// Why: DigitalOcean's nameservers cache negative answers (NXDOMAIN) for the
// zone's negative TTL (30 minutes). Between orders a label would otherwise
// have no records, and lego looks the label up (following the partner's
// CNAME, and finding the zone) *before* it creates the challenge record.
// That lookup would cache NXDOMAIN and hide the new record until the order
// times out. With a placeholder the name always exists, so changes to its
// TXT set become visible within the record TTL.
package dodns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	DefaultBaseURL = "https://api.digitalocean.com"
	// PlaceholderValue identifies acme-steward's placeholder records.
	PlaceholderValue = "acme-steward placeholder: keeps this name resolvable; do not delete"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New uses DO_API_URL if set (as lego's DigitalOcean provider does).
func New(token string) *Client {
	base := os.Getenv("DO_API_URL")
	if base == "" {
		base = DefaultBaseURL
	}
	return &Client{BaseURL: strings.TrimSuffix(base, "/"), Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type Record struct {
	ID   int    `json:"id,omitempty"`
	Type string `json:"type"`
	Name string `json:"name"` // relative to the zone
	Data string `json:"data"`
	TTL  int    `json:"ttl,omitempty"`
}

// TXT returns the TXT records at name (relative to zone).
func (c *Client) TXT(ctx context.Context, zone, name string) ([]Record, error) {
	q := url.Values{"type": {"TXT"}, "name": {name + "." + zone}, "per_page": {"200"}}
	var resp struct {
		Records []Record `json:"domain_records"`
	}
	if err := c.do(ctx, http.MethodGet, "/v2/domains/"+zone+"/records?"+q.Encode(), nil, &resp); err != nil {
		return nil, err
	}
	var out []Record
	for _, r := range resp.Records {
		if r.Type == "TXT" && strings.EqualFold(r.Name, name) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (c *Client) Create(ctx context.Context, zone string, r Record) (Record, error) {
	var resp struct {
		Record Record `json:"domain_record"`
	}
	err := c.do(ctx, http.MethodPost, "/v2/domains/"+zone+"/records", r, &resp)
	return resp.Record, err
}

// EnsurePlaceholder creates the placeholder TXT at name if it is missing.
// It reports whether a record was created.
func (c *Client) EnsurePlaceholder(ctx context.Context, zone, name string, ttl int) (bool, error) {
	recs, err := c.TXT(ctx, zone, name)
	if err != nil {
		return false, err
	}
	for _, r := range recs {
		if strings.Trim(r.Data, `"`) == PlaceholderValue {
			return false, nil
		}
	}
	_, err = c.Create(ctx, zone, Record{Type: "TXT", Name: name, Data: PlaceholderValue, TTL: ttl})
	return err == nil, err
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("digitalocean %s %s: %s: %s", method, strings.SplitN(path, "?", 2)[0], resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}
