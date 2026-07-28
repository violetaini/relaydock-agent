package collector

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"mmw-agent/internal/constants"
)

// XrayMetrics 表示 Xray /debug/vars 的响应结构。
type XrayMetrics struct {
	Stats *XrayStats `json:"stats,omitempty"`
}

// XrayStats 包含入站、出站和用户维度的流量统计。
type XrayStats struct {
	Inbound  map[string]TrafficData `json:"inbound,omitempty"`
	Outbound map[string]TrafficData `json:"outbound,omitempty"`
	User     map[string]TrafficData `json:"user,omitempty"`
}

// TrafficData 表示上下行流量（字节）。
type TrafficData struct {
	Uplink   int64 `json:"uplink"`
	Downlink int64 `json:"downlink"`
}

// XrayConfig 用于读取 xray config.json 中的 metrics 监听配置。
type XrayConfig struct {
	Log       json.RawMessage `json:"log,omitempty"`
	DNS       json.RawMessage `json:"dns,omitempty"`
	API       json.RawMessage `json:"api,omitempty"`
	Stats     json.RawMessage `json:"stats,omitempty"`
	Policy    json.RawMessage `json:"policy,omitempty"`
	Routing   json.RawMessage `json:"routing,omitempty"`
	Inbounds  json.RawMessage `json:"inbounds,omitempty"`
	Outbounds json.RawMessage `json:"outbounds,omitempty"`
	Metrics   *MetricsConfig  `json:"metrics,omitempty"`
}

// MetricsConfig 对应 xray 配置中的 metrics 段。
type MetricsConfig struct {
	Tag    string `json:"tag,omitempty"`
	Listen string `json:"listen,omitempty"` // 格式示例: "127.0.0.1:38889"
}

// Collector 负责采集 Xray 流量指标。
type Collector struct {
	httpClient         *http.Client
	defaultMetricsPort int
	defaultMetricsHost string
}

// 创建指标采集器。
func NewCollector() *Collector {
	return &Collector{
		httpClient:         &http.Client{Timeout: constants.DefaultHTTPClientTimeout},
		defaultMetricsPort: constants.DefaultMetricsPort,
		defaultMetricsHost: constants.DefaultMetricsHost,
	}
}

// 从 xray 配置中读取 metrics 监听地址和端口。
func (c *Collector) GetMetricsPortFromConfig(configPath string) (string, int, error) {
	if configPath == "" {
		return constants.DefaultMetricsHost, c.defaultMetricsPort, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return constants.DefaultMetricsHost, c.defaultMetricsPort, fmt.Errorf("read config file: %w", err)
	}

	var config XrayConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return constants.DefaultMetricsHost, c.defaultMetricsPort, fmt.Errorf("parse config file: %w", err)
	}

	if config.Metrics == nil || config.Metrics.Listen == "" {
		return "", 0, fmt.Errorf("metrics not configured in xray config")
	}

	// 解析监听地址，支持 "127.0.0.1:38889" 或 ":38889"
	listen := config.Metrics.Listen
	host := constants.DefaultMetricsHost
	var port int

	if strings.Contains(listen, ":") {
		parts := strings.Split(listen, ":")
		if len(parts) == 2 {
			if parts[0] != "" {
				host = parts[0]
			}
			p, err := strconv.Atoi(parts[1])
			if err != nil {
				return "", 0, fmt.Errorf("invalid metrics port: %s", parts[1])
			}
			port = p
		}
	} else {
		// 兼容仅填写端口的写法
		p, err := strconv.Atoi(listen)
		if err != nil {
			return "", 0, fmt.Errorf("invalid metrics listen format: %s", listen)
		}
		port = p
	}

	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid metrics port: %d", port)
	}

	return host, port, nil
}

// 从 Xray 的 /debug/vars 拉取指标。
func (c *Collector) FetchMetrics(host string, port int) (*XrayMetrics, error) {
	url := fmt.Sprintf("http://%s:%d/debug/vars", host, port)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var metrics XrayMetrics
	if err := json.Unmarshal(body, &metrics); err != nil {
		return nil, fmt.Errorf("unmarshal metrics: %w", err)
	}

	return &metrics, nil
}

// 将 source 的统计合并到 dest。
func MergeStats(dest, source *XrayStats) {
	if source == nil {
		return
	}
	if dest.Inbound == nil {
		dest.Inbound = make(map[string]TrafficData)
	}
	if dest.Outbound == nil {
		dest.Outbound = make(map[string]TrafficData)
	}
	if dest.User == nil {
		dest.User = make(map[string]TrafficData)
	}

	for k, v := range source.Inbound {
		dest.Inbound[k] = v
	}
	for k, v := range source.Outbound {
		dest.Outbound[k] = v
	}
	for k, v := range source.User {
		dest.User[k] = v
	}
}
