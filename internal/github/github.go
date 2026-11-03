// Package github scans the parts of GitHub that never reach a clone: repository
// metadata, issues and pull requests, their comments and reviews, releases,
// gists, and whether a former username is free for someone else to take.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0-draft/kwangmyong/internal/rules"
	"github.com/0-draft/kwangmyong/internal/scan"
)

// Surface is the finding surface for everything this package reports.
const Surface = "github"

// Client is a minimal GitHub REST client.
type Client struct {
	HTTP  *http.Client
	Base  string
	token string
}

// NewClient authenticates with GH_TOKEN, GITHUB_TOKEN, or `gh auth token`.
func NewClient() (*Client, error) {
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		out, err := exec.Command("gh", "auth", "token").Output()
		if err != nil {
			return nil, errors.New("no GitHub token: set GH_TOKEN or GITHUB_TOKEN, or log in with `gh auth login`")
		}
		token = strings.TrimSpace(string(out))
	}
	base := os.Getenv("GITHUB_API_URL")
	if base == "" {
		base = "https://api.github.com"
	}
	return &Client{HTTP: &http.Client{Timeout: 60 * time.Second}, Base: strings.TrimSuffix(base, "/"), token: token}, nil
}

// StatusError is a non-2xx response.
type StatusError struct {
	Code int
	Path string
}

func (e *StatusError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.Path, e.Code) }

func isStatus(err error, codes ...int) bool {
	var se *StatusError
	if !errors.As(err, &se) {
		return false
	}
	for _, c := range codes {
		if se.Code == c {
			return true
		}
	}
	return false
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func (c *Client) get(ctx context.Context, pathOrURL string) ([]byte, string, error) {
	u := pathOrURL
	if !strings.HasPrefix(u, "http") {
		u = c.Base + pathOrURL
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if c.token != "" && sameHost(u, c.Base) {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, "", err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		_ = resp.Body.Close()
		if err != nil {
			return nil, "", err
		}
		if (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) && attempt < 3 {
			if wait := retryAfter(resp.Header); wait > 0 && wait <= 90*time.Second {
				select {
				case <-time.After(wait):
					continue
				case <-ctx.Done():
					return nil, "", ctx.Err()
				}
			}
		}
		if resp.StatusCode/100 != 2 {
			return nil, "", &StatusError{Code: resp.StatusCode, Path: redactURL(u)}
		}
		next := ""
		if m := linkNext.FindStringSubmatch(resp.Header.Get("Link")); m != nil {
			next = m[1]
		}
		return body, next, nil
	}
}

func sameHost(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && ua.Host == ub.Host
}

func redactURL(u string) string {
	if p, err := url.Parse(u); err == nil {
		return p.Path
	}
	return u
}

func retryAfter(h http.Header) time.Duration {
	if s := h.Get("Retry-After"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	if h.Get("X-RateLimit-Remaining") == "0" {
		if n, err := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			return time.Until(time.Unix(n, 0)) + time.Second
		}
	}
	return 0
}

// each pages through a JSON array endpoint.
func each[T any](ctx context.Context, c *Client, path string, fn func(T)) error {
	next := path
	for next != "" {
		body, n, err := c.get(ctx, next)
		if err != nil {
			return err
		}
		var page []T
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("%s: %w", redactURL(next), err)
		}
		for _, v := range page {
			fn(v)
		}
		next = n
	}
	return nil
}

// Options selects what to scan.
type Options struct {
	Owner           string // user or organization
	Repo            string // optional: a single repository
	IncludeForks    bool
	IncludeArchived bool
	Reviews         bool     // one extra request per pull request
	Gists           bool     // the owner's gists (secret ones too when it is you)
	Handles         []string // former usernames to check for takeover
	Concurrency     int
}

// Scanner runs a GitHub scan.
type Scanner struct {
	C *Client
	M *rules.Matcher

	mu  sync.Mutex
	out []scan.Finding
}

type repo struct {
	FullName    string   `json:"full_name"`
	Description string   `json:"description"`
	Homepage    string   `json:"homepage"`
	Topics      []string `json:"topics"`
	Fork        bool     `json:"fork"`
	Archived    bool     `json:"archived"`
	HasIssues   bool     `json:"has_issues"`
}

type issue struct {
	Number      int             `json:"number"`
	Title       string          `json:"title"`
	Body        string          `json:"body"`
	PullRequest json.RawMessage `json:"pull_request"`
}

type comment struct {
	ID       int64  `json:"id"`
	Body     string `json:"body"`
	IssueURL string `json:"issue_url"`
	PRURL    string `json:"pull_request_url"`
	Path     string `json:"path"`
}

type release struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	Body    string `json:"body"`
}

type gist struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Files       map[string]struct {
		Filename string `json:"filename"`
		RawURL   string `json:"raw_url"`
		Size     int64  `json:"size"`
	} `json:"files"`
}

func (s *Scanner) text(location, field, text string) {
	for i, line := range strings.Split(text, "\n") {
		for _, mt := range s.M.Find(line) {
			s.mu.Lock()
			s.out = append(s.out, scan.Finding{
				RuleID: mt.RuleID, Severity: mt.Severity.String(), Surface: Surface,
				Location: location, Field: field, Line: i + 1, Count: 1,
				Value: mt.Value, Redacted: rules.Redact(mt.Value),
			})
			s.mu.Unlock()
		}
	}
}

// Run scans per Options.
func (s *Scanner) Run(ctx context.Context, opt Options) ([]scan.Finding, error) {
	if opt.Concurrency <= 0 {
		opt.Concurrency = 4
	}
	if err := s.handles(ctx, opt.Handles); err != nil {
		return nil, err
	}
	me := ""
	if body, _, err := s.C.get(ctx, "/user"); err == nil {
		var u struct {
			Login string `json:"login"`
		}
		_ = json.Unmarshal(body, &u)
		me = u.Login
	}
	repos, err := s.repos(ctx, opt, me)
	if err != nil {
		return nil, err
	}
	sem := make(chan struct{}, opt.Concurrency)
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error
	for _, r := range repos {
		wg.Add(1)
		sem <- struct{}{}
		go func(r repo) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := s.repo(ctx, r, opt); err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("%s: %w", r.FullName, err)
				}
				errMu.Unlock()
			}
		}(r)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if opt.Gists && opt.Repo == "" {
		if err := s.gists(ctx, opt.Owner, me); err != nil {
			return nil, err
		}
	}
	return s.out, nil
}

func (s *Scanner) repos(ctx context.Context, opt Options, me string) ([]repo, error) {
	if opt.Repo != "" {
		body, _, err := s.C.get(ctx, "/repos/"+opt.Owner+"/"+opt.Repo)
		if err != nil {
			return nil, err
		}
		var r repo
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, err
		}
		return []repo{r}, nil
	}
	var all []repo
	collect := func(r repo) { all = append(all, r) }
	var err error
	switch {
	case strings.EqualFold(opt.Owner, me):
		err = each(ctx, s.C, "/user/repos?affiliation=owner&per_page=100", collect)
	default:
		err = each(ctx, s.C, "/orgs/"+url.PathEscape(opt.Owner)+"/repos?type=all&per_page=100", collect)
		if isStatus(err, http.StatusNotFound) {
			all = nil
			err = each(ctx, s.C, "/users/"+url.PathEscape(opt.Owner)+"/repos?type=owner&per_page=100", collect)
		}
	}
	if err != nil {
		return nil, err
	}
	var out []repo
	for _, r := range all {
		if (r.Fork && !opt.IncludeForks) || (r.Archived && !opt.IncludeArchived) {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func (s *Scanner) repo(ctx context.Context, r repo, opt Options) error {
	base := "/repos/" + r.FullName
	s.text(r.FullName, "repo.description", r.Description)
	s.text(r.FullName, "repo.homepage", r.Homepage)
	s.text(r.FullName, "repo.topics", strings.Join(r.Topics, " "))

	var prs []int
	err := each(ctx, s.C, base+"/issues?state=all&per_page=100", func(i issue) {
		kind := "issue"
		if len(i.PullRequest) > 0 && string(i.PullRequest) != "null" {
			kind = "pr"
			prs = append(prs, i.Number)
		}
		loc := fmt.Sprintf("%s#%d", r.FullName, i.Number)
		s.text(loc, kind+".title", i.Title)
		s.text(loc, kind+".body", i.Body)
	})
	if err != nil && !isStatus(err, http.StatusNotFound, http.StatusGone) {
		return err
	}
	err = each(ctx, s.C, base+"/issues/comments?per_page=100", func(c comment) {
		s.text(fmt.Sprintf("%s#%s comment %d", r.FullName, lastSegment(c.IssueURL), c.ID), "comment.body", c.Body)
	})
	if err != nil && !isStatus(err, http.StatusNotFound, http.StatusGone) {
		return err
	}
	err = each(ctx, s.C, base+"/pulls/comments?per_page=100", func(c comment) {
		s.text(fmt.Sprintf("%s#%s review-comment %d", r.FullName, lastSegment(c.PRURL), c.ID), "review-comment.body", c.Body)
	})
	if err != nil && !isStatus(err, http.StatusNotFound, http.StatusGone) {
		return err
	}
	if opt.Reviews {
		for _, n := range prs {
			err := each(ctx, s.C, fmt.Sprintf("%s/pulls/%d/reviews?per_page=100", base, n), func(c comment) {
				s.text(fmt.Sprintf("%s#%d review %d", r.FullName, n, c.ID), "review.body", c.Body)
			})
			if err != nil && !isStatus(err, http.StatusNotFound, http.StatusGone) {
				return err
			}
		}
	}
	err = each(ctx, s.C, base+"/releases?per_page=100", func(rel release) {
		loc := r.FullName + " release " + rel.TagName
		s.text(loc, "release.name", rel.Name)
		s.text(loc, "release.body", rel.Body)
	})
	if err != nil && !isStatus(err, http.StatusNotFound, http.StatusGone) {
		return err
	}
	return nil
}

func (s *Scanner) gists(ctx context.Context, owner, me string) error {
	path := "/users/" + url.PathEscape(owner) + "/gists?per_page=100"
	if strings.EqualFold(owner, me) {
		path = "/gists?per_page=100" // includes secret gists
	}
	var gs []gist
	err := each(ctx, s.C, path, func(g gist) { gs = append(gs, g) })
	if isStatus(err, http.StatusNotFound) {
		return nil // an organization has no gists
	}
	if err != nil {
		return err
	}
	for _, g := range gs {
		loc := "gist " + g.ID
		s.text(loc, "gist.description", g.Description)
		for name, f := range g.Files {
			s.text(loc, "gist.filename", name)
			if f.RawURL == "" || f.Size > 5<<20 {
				continue
			}
			body, _, err := s.C.get(ctx, f.RawURL)
			if err != nil {
				continue
			}
			s.text(loc+" "+name, "gist.content", string(body))
		}
	}
	return nil
}

// handles reports declared logins that are free to register on GitHub. A
// renamed account's old name keeps redirecting until someone takes it; then
// every github.com/<old>/... link, go module path and clone URL points at them.
func (s *Scanner) handles(ctx context.Context, handles []string) error {
	for _, h := range handles {
		if !validHandle.MatchString(h) {
			continue
		}
		_, _, err := s.C.get(ctx, "/users/"+url.PathEscape(h))
		switch {
		case err == nil:
		case isStatus(err, http.StatusNotFound):
			s.mu.Lock()
			s.out = append(s.out, scan.Finding{
				RuleID: "github.unclaimed-handle", Severity: "warn", Surface: Surface,
				Location: "github.com/" + rules.Redact(h), Field: "user", Count: 1,
				Value: h, Redacted: rules.Redact(h),
			})
			s.mu.Unlock()
		default:
			return err
		}
	}
	return nil
}

var validHandle = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)

func lastSegment(u string) string {
	if i := strings.LastIndex(u, "/"); i >= 0 {
		return u[i+1:]
	}
	return u
}
