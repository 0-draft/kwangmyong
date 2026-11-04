package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kanywst/kwangmyong/internal/identity"
	"github.com/kanywst/kwangmyong/internal/rules"
)

func fakeGitHub(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	var srv *httptest.Server
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) { j(w, map[string]string{"login": "someone-else"}) })
	mux.HandleFunc("/users/oldhandle", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	mux.HandleFunc("/users/takenhandle", func(w http.ResponseWriter, _ *http.Request) { j(w, map[string]string{"login": "takenhandle"}) })
	mux.HandleFunc("/orgs/acme/repos", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "" {
			w.Header().Set("Link", fmt.Sprintf(`<%s/orgs/acme/repos?page=2>; rel="next"`, srv.URL))
			j(w, []map[string]any{{"full_name": "acme/app", "description": "by Taro Yamada"}})
			return
		}
		j(w, []map[string]any{{"full_name": "acme/old", "archived": true}, {"full_name": "acme/fork", "fork": true}})
	})
	mux.HandleFunc("/repos/acme/app/issues", func(w http.ResponseWriter, _ *http.Request) {
		j(w, []map[string]any{
			{"number": 1, "title": "bug", "body": "trace: /Users/tyamada/src/app/main.go:12"},
			{"number": 2, "title": "feat", "body": "clean", "pull_request": map[string]any{}},
		})
	})
	mux.HandleFunc("/repos/acme/app/issues/comments", func(w http.ResponseWriter, _ *http.Request) {
		j(w, []map[string]any{{"id": 7, "issue_url": "https://x/repos/acme/app/issues/1", "body": "ping taro@example.com"}})
	})
	mux.HandleFunc("/repos/acme/app/pulls/comments", func(w http.ResponseWriter, _ *http.Request) { j(w, []any{}) })
	mux.HandleFunc("/repos/acme/app/pulls/2/reviews", func(w http.ResponseWriter, _ *http.Request) {
		j(w, []map[string]any{{"id": 9, "body": "looks fine, tyamada"}})
	})
	mux.HandleFunc("/repos/acme/app/releases", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "gone", http.StatusGone) })
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestScanOrg(t *testing.T) {
	srv := fakeGitHub(t)
	m, err := rules.New(identity.Expand(identity.Identity{
		Names: []string{"Taro Yamada"}, Logins: []string{"tyamada"}, Emails: []string{"taro@example.com"},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &Scanner{C: &Client{HTTP: srv.Client(), Base: srv.URL}, M: m}
	got, err := s.Run(context.Background(), Options{Owner: "acme", Reviews: true, Handles: []string{"oldhandle", "takenhandle", "not/valid"}})
	if err != nil {
		t.Fatal(err)
	}
	var fields []string
	for _, f := range got {
		fields = append(fields, f.RuleID+"@"+f.Field)
		if strings.Contains(f.Location, "acme/old") || strings.Contains(f.Location, "acme/fork") {
			t.Errorf("archived/fork repo scanned: %+v", f)
		}
	}
	joined := strings.Join(fields, " ")
	for _, want := range []string{
		"github.unclaimed-handle@user", "identity.name@repo.description", "@issue.body",
		"identity.email@comment.body", "@review.body",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in %s", want, joined)
		}
	}
	if strings.Count(joined, "unclaimed-handle") != 1 {
		t.Errorf("only the free handle should be reported: %s", joined)
	}
}
