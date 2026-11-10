package acmecert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	cloudflareAPI = "https://api.cloudflare.com/client/v4"
)

// CloudflareSolver 通过 Cloudflare API 管理 DNS-01 挑战的 TXT 记录。
type CloudflareSolver struct {
	// Token 是 Cloudflare API Token，需具备对应 Zone 的 DNS 编辑权限
	// （Zone.DNS Edit）。不得与 Key 同时为空。
	Token string

	// ZoneID 是目标域名的 Zone ID，可在 Cloudflare 控制台获取。
	// 为空时根据域名自动查询 Zone。
	ZoneID string

	client *http.Client
}

// NewCloudflareSolver 创建一个 Cloudflare DNS-01 求解器。
func NewCloudflareSolver(token, zoneID string) *CloudflareSolver {
	return &CloudflareSolver{
		Token:  token,
		ZoneID: zoneID,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Present 添加一条 _acme-challenge TXT 记录。
func (s *CloudflareSolver) Present(ctx context.Context, domain, token, keyAuth string) error {
	zoneID, err := s.resolveZone(ctx, domain)
	if err != nil {
		return err
	}
	recordName := dns01RecordName(domain)
	return s.createTXTRecord(ctx, zoneID, recordName, keyAuth)
}

// CleanUp 删除之前添加的 _acme-challenge TXT 记录。
func (s *CloudflareSolver) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	zoneID, err := s.resolveZone(ctx, domain)
	if err != nil {
		return err
	}
	recordName := dns01RecordName(domain)
	return s.deleteTXTRecord(ctx, zoneID, recordName)
}

// dns01RecordName 返回 DNS-01 挑战的 TXT 记录名。
func dns01RecordName(domain string) string {
	return "_acme-challenge." + strings.TrimSuffix(domain, ".")
}

// resolveZone 返回域名的 Zone ID。
func (s *CloudflareSolver) resolveZone(ctx context.Context, domain string) (string, error) {
	if s.ZoneID != "" {
		return s.ZoneID, nil
	}
	// 自动查询：对域名逐级向上查找匹配的 Zone。
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	for i := 0; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		id, err := s.zoneIDByName(ctx, candidate)
		if err == nil {
			return id, nil
		}
	}
	return "", fmt.Errorf("acmecert: no Cloudflare zone found for %q", domain)
}

// cfZone represents a Cloudflare zone in list responses.
type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfResponse struct {
	Success  bool            `json:"success"`
	Errors   []cfError       `json:"errors"`
	Result   json.RawMessage `json:"result"`
	Messages []cfMessage     `json:"messages"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *CloudflareSolver) do(ctx context.Context, method, path string, body any, out any) error {
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		buf = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, cloudflareAPI+path, buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var cf cfResponse
	if err := json.Unmarshal(data, &cf); err != nil {
		return err
	}
	if !cf.Success {
		if len(cf.Errors) > 0 {
			return fmt.Errorf("acmecert: cloudflare API error: %s", cf.Errors[0].Message)
		}
		return fmt.Errorf("acmecert: cloudflare API returned failure")
	}
	if out != nil {
		return json.Unmarshal(cf.Result, out)
	}
	return nil
}

func (s *CloudflareSolver) zoneIDByName(ctx context.Context, name string) (string, error) {
	q := url.Values{}
	q.Set("name", name)
	var zones []cfZone
	if err := s.do(ctx, http.MethodGet, "/zones?"+q.Encode(), nil, &zones); err != nil {
		return "", err
	}
	if len(zones) == 0 {
		return "", fmt.Errorf("acmecert: zone %q not found", name)
	}
	return zones[0].ID, nil
}

type cfDNSRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

func (s *CloudflareSolver) createTXTRecord(ctx context.Context, zoneID, name, content string) error {
	rec := cfDNSRecord{
		Type:    "TXT",
		Name:    name,
		Content: content,
		TTL:     120,
	}
	return s.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", rec, nil)
}

func (s *CloudflareSolver) deleteTXTRecord(ctx context.Context, zoneID, name string) error {
	// 查询匹配的记录并删除。
	q := url.Values{}
	q.Set("type", "TXT")
	q.Set("name", name)
	var records []cfDNSRecord
	if err := s.do(ctx, http.MethodGet, "/zones/"+zoneID+"/dns_records?"+q.Encode(), nil, &records); err != nil {
		return err
	}
	for _, r := range records {
		if err := s.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+r.ID, nil, nil); err != nil {
			return err
		}
	}
	return nil
}
