package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/snd-primary/ajiro/internal/webpot"
)

const queryToken = "query-token"

var t0 = time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)

func seedEvent(i int, ts time.Time, typ, ip, path string) *webpot.Event {
	ev := httpEvent()
	ev.ID = fmt.Sprintf("01a16fd8-dbfc-7b21-976f-%012x", i)
	ev.Time, ev.EventType, ev.SrcIP = ts, typ, ip
	switch typ {
	case webpot.EventHTTPRequest:
		ev.HTTP.Path = path
	case webpot.EventConnNoRequest:
		ev.HTTP = nil
	case webpot.EventRateLimited:
		ev.HTTP, ev.Raw = nil, nil
		ev.Dropped = &webpot.DropInfo{Count: 10, Since: ts, Reason: "rate_limit"}
	}
	return ev
}

// newTestAPI seeds:
//
//	00:10  http /.env        192.0.2.1
//	00:20  http /.env        192.0.2.2
//	00:30  http /wp-login    192.0.2.1
//	01:05  conn_no_request   198.51.100.7
//	01:10  rate_limited x10  198.51.100.7
//	01:20  http /.env        192.0.2.3
func newTestAPI(t *testing.T) *QueryAPI {
	t.Helper()
	db := openTestDB(t)
	evs := []*webpot.Event{
		seedEvent(1, t0.Add(10*time.Minute), webpot.EventHTTPRequest, "192.0.2.1", "/.env"),
		seedEvent(2, t0.Add(20*time.Minute), webpot.EventHTTPRequest, "192.0.2.2", "/.env"),
		seedEvent(3, t0.Add(30*time.Minute), webpot.EventHTTPRequest, "192.0.2.1", "/wp-login.php"),
		seedEvent(4, t0.Add(65*time.Minute), webpot.EventConnNoRequest, "198.51.100.7", ""),
		seedEvent(5, t0.Add(70*time.Minute), webpot.EventRateLimited, "198.51.100.7", ""),
		seedEvent(6, t0.Add(80*time.Minute), webpot.EventHTTPRequest, "192.0.2.3", "/.env"),
	}
	var recs []Record
	for _, ev := range evs {
		recs = append(recs, Record{ReceivedAt: ev.Time, Event: ev})
	}
	if err := db.Insert(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	a, err := NewQueryAPI(db, queryToken)
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return t0.Add(24 * time.Hour) }
	return a
}

func get(a http.Handler, path string, params url.Values, token string) *httptest.ResponseRecorder {
	if params != nil {
		path += "?" + params.Encode()
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	return rec
}

func getJSON(t *testing.T, a http.Handler, path string, params url.Values, v any) {
	t.Helper()
	rec := get(a, path, params, queryToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s?%s: status = %d, body = %s", path, params.Encode(), rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("%s: missing safety headers", path)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatal(err)
	}
}

func TestQueryAPIAuth(t *testing.T) {
	a := newTestAPI(t)
	for _, tok := range []string{"", testToken, "wrong"} {
		if rec := get(a, "/api/summary", nil, tok); rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q: status = %d", tok, rec.Code)
		}
	}
	if _, err := NewQueryAPI(nil, ""); err == nil {
		t.Error("empty token accepted")
	}
}

func TestSummary(t *testing.T) {
	a := newTestAPI(t)
	var s Summary
	getJSON(t, a, "/api/summary", nil, &s)
	want := Summary{Events: 5, HTTPRequests: 4, ConnNoRequest: 1, RateLimited: 10, DistinctSrcIPs: 4}
	first, last := s.First, s.Last
	s.First, s.Last = nil, nil
	if s != want {
		t.Errorf("summary = %+v, want %+v", s, want)
	}
	if first == nil || !first.Equal(t0.Add(10*time.Minute)) || last == nil || !last.Equal(t0.Add(80*time.Minute)) {
		t.Errorf("first = %v, last = %v", first, last)
	}

	getJSON(t, a, "/api/summary", url.Values{"from": {"2026-10-21T01:00:00Z"}}, &s)
	if s.Events != 2 || s.HTTPRequests != 1 {
		t.Errorf("summary from 01:00 = %+v", s)
	}
}

func TestTimeseries(t *testing.T) {
	a := newTestAPI(t)
	var resp struct {
		Points []Point `json:"points"`
	}
	getJSON(t, a, "/api/timeseries", url.Values{"bucket": {"hour"}}, &resp)
	got := map[string]int{}
	for _, p := range resp.Points {
		got[p.T.Format("15")+" "+p.EventType] = p.N
	}
	want := map[string]int{"00 http_request": 3, "01 conn_no_request": 1, "01 rate_limited": 10, "01 http_request": 1}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("points = %v, want %v", got, want)
	}

	getJSON(t, a, "/api/timeseries", url.Values{"bucket": {"day"}, "path": {"/.env"}}, &resp)
	if len(resp.Points) != 1 || resp.Points[0].N != 3 {
		t.Errorf("/.env per day = %+v", resp.Points)
	}
}

func TestTop(t *testing.T) {
	a := newTestAPI(t)
	var resp struct {
		Items []TopItem `json:"items"`
	}
	getJSON(t, a, "/api/top", url.Values{"field": {"path"}}, &resp)
	if len(resp.Items) != 2 || resp.Items[0].Value != "/.env" || resp.Items[0].N != 3 || resp.Items[0].Sources != 3 {
		t.Errorf("top paths = %+v", resp.Items)
	}
	getJSON(t, a, "/api/top", url.Values{"field": {"src_ip"}, "limit": {"1"}}, &resp)
	if len(resp.Items) != 1 || resp.Items[0].Value != "192.0.2.1" {
		t.Errorf("top src_ip = %+v", resp.Items)
	}
}

func TestEventsPagination(t *testing.T) {
	a := newTestAPI(t)
	var page struct {
		Events []EventRow `json:"events"`
		Next   string     `json:"next"`
	}
	var ids []string
	params := url.Values{"limit": {"2"}}
	for range 5 {
		getJSON(t, a, "/api/events", params, &page)
		for _, e := range page.Events {
			ids = append(ids, e.ID[len(e.ID)-1:])
		}
		if page.Next == "" {
			break
		}
		params.Set("before", page.Next)
		page.Next = ""
	}
	if fmt.Sprint(ids) != "[6 5 4 3 2 1]" {
		t.Errorf("ids = %v", ids)
	}
}

func TestEventsFilters(t *testing.T) {
	a := newTestAPI(t)
	var page struct {
		Events []EventRow `json:"events"`
	}
	cases := []struct {
		params url.Values
		n      int
	}{
		{url.Values{"event_type": {"conn_no_request"}}, 1},
		{url.Values{"src_ip": {"192.0.2.1"}}, 2},
		{url.Values{"path": {"/.env"}}, 3},
		{url.Values{"path": {"/.env' OR '1'='1"}}, 0},
		{url.Values{"to": {"2026-10-21T00:15:00Z"}}, 1},
	}
	for _, c := range cases {
		getJSON(t, a, "/api/events", c.params, &page)
		if len(page.Events) != c.n {
			t.Errorf("%s: %d events, want %d", c.params.Encode(), len(page.Events), c.n)
		}
	}
	getJSON(t, a, "/api/events", url.Values{"event_type": {"rate_limited"}}, &page)
	if e := page.Events[0]; e.DroppedCount == nil || *e.DroppedCount != 10 || e.Path != nil {
		t.Errorf("rate_limited row = %+v", e)
	}
}

func TestEventDetail(t *testing.T) {
	a := newTestAPI(t)
	id := seedEvent(1, t0, "", "", "").ID
	var d struct {
		ReceivedAt time.Time    `json:"received_at"`
		Event      webpot.Event `json:"event"`
	}
	getJSON(t, a, "/api/events/"+id, nil, &d)
	if d.Event.ID != id || d.Event.HTTP.Path != "/.env" || d.Event.Raw == nil {
		t.Errorf("detail = %+v", d.Event)
	}
	if rec := get(a, "/api/events/01a16fd8-dbfc-7b21-976f-0000000000ff", nil, queryToken); rec.Code != http.StatusNotFound {
		t.Errorf("missing id: status = %d", rec.Code)
	}
}

func TestQueryAPIRejectsBadParams(t *testing.T) {
	a := newTestAPI(t)
	bad := []struct {
		path   string
		params url.Values
	}{
		{"/api/summary", url.Values{"from": {"yesterday"}}},
		{"/api/summary", url.Values{"from": {"2026-10-22T00:00:00Z"}, "to": {"2026-10-21T00:00:00Z"}}},
		{"/api/timeseries", url.Values{"bucket": {"week"}}},
		{"/api/top", url.Values{"field": {"http_path; DROP TABLE events"}}},
		{"/api/top", url.Values{"field": {"path"}, "limit": {"501"}}},
		{"/api/top", url.Values{"field": {"path"}, "limit": {"-1"}}},
		{"/api/events", url.Values{"before": {"' OR 1=1"}}},
		{"/api/events", url.Values{"event_type": {"shell"}}},
		{"/api/events", url.Values{"src_ip": {"not-an-ip"}}},
		{"/api/events/..%2F..%2Fetc%2Fpasswd", nil},
	}
	for _, c := range bad {
		if rec := get(a, c.path, c.params, queryToken); rec.Code != http.StatusBadRequest {
			t.Errorf("%s?%s: status = %d, want 400", c.path, c.params.Encode(), rec.Code)
		}
	}
	if rec := get(a, "/api/summary", nil, queryToken); rec.Code != http.StatusOK {
		t.Errorf("db unusable after bad params: %d", rec.Code)
	}
}
