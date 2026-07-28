// client.go — Cloudflare WARP API HTTP client。
//
// 参考 3x-ui web/service/warp.go 实现:直接调 Cloudflare 客户端注册 API,
// 不依赖 wgcf 二进制。必需 header `CF-Client-Version: a-6.30-3596`(API 校验)。
//
// 接口:
//   - Register: POST /reg(注册新 WARP 设备)
//   - GetConfig: GET /reg/{device_id}(获取完整 wg peer 信息)
//   - UpdateLicense: PUT /reg/{device_id}/account(升级 WARP+)
//   - Delete: DELETE /reg/{device_id}(注销设备)

package warp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	warpAPIBase   = "https://api.cloudflareclient.com/v0a4005"
	warpClientVer = "a-6.30-3596"
)

var warpHTTPClient = &http.Client{Timeout: 30 * time.Second}

// RegisterResp 是 Cloudflare WARP 注册 API 的核心字段(只解出我们需要的)。
type RegisterResp struct {
	ID      string `json:"id"`    // device_id
	Token   string `json:"token"` // access_token
	Account struct {
		License string `json:"license"`
	} `json:"account"`
	Config struct {
		ClientID  string `json:"client_id"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

// Register 用 publicKey 注册新 WARP 设备。返回完整 RegisterResp。
// Cloudflare 自动分配 v4/v6 地址 + 选 peer + 生成 client_id。
func Register(ctx context.Context, publicKey string) (*RegisterResp, error) {
	hostname, _ := os.Hostname()
	body, _ := json.Marshal(map[string]any{
		"key":   publicKey,
		"tos":   time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"type":  "PC",
		"model": "mmw-agent",
		"name":  hostname,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, warpAPIBase+"/reg", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("CF-Client-Version", warpClientVer)
	req.Header.Set("Content-Type", "application/json")

	respBody, err := doRequest(req)
	if err != nil {
		return nil, err
	}
	var out RegisterResp
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode register response: %w", err)
	}
	if out.ID == "" || out.Token == "" {
		return nil, errors.New("warp register: missing id or token in response")
	}
	return &out, nil
}

// GetConfig 拿当前已注册设备的完整配置(刷新 peer 信息用)。
func GetConfig(ctx context.Context, deviceID, accessToken string) (*RegisterResp, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/reg/%s", warpAPIBase, deviceID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("CF-Client-Version", warpClientVer)

	respBody, err := doRequest(req)
	if err != nil {
		return nil, err
	}
	var out RegisterResp
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode config response: %w", err)
	}
	return &out, nil
}

// UpdateLicense 升级到 WARP+(license 通过 1.1.1.1 app 获取)。
// 升级后 Cloudflare 会调整 peer / 流量上限,通常需要再调一次 GetConfig 刷新配置。
func UpdateLicense(ctx context.Context, deviceID, accessToken, license string) error {
	body, _ := json.Marshal(map[string]string{"license": license})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		fmt.Sprintf("%s/reg/%s/account", warpAPIBase, deviceID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("CF-Client-Version", warpClientVer)

	if _, err := doRequest(req); err != nil {
		return err
	}
	return nil
}

// Delete 注销当前设备。注销后该 device_id 不可再用,客户端要重新 Register。
func Delete(ctx context.Context, deviceID, accessToken string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		fmt.Sprintf("%s/reg/%s", warpAPIBase, deviceID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("CF-Client-Version", warpClientVer)

	resp, err := warpHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 204 No Content 是预期结果;404 视为"已经不存在",也算成功(本地清状态即可)。
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("warp delete returned %d: %s", resp.StatusCode, string(body))
}

func doRequest(req *http.Request) ([]byte, error) {
	resp, err := warpHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if msg := parseWarpError(body); msg != "" {
			return nil, fmt.Errorf("warp api %s %s: %s", req.Method, req.URL.Path, msg)
		}
		return nil, fmt.Errorf("warp api %s %s returned %d: %s",
			req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func parseWarpError(body []byte) string {
	var env struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return ""
	}
	if len(env.Errors) == 0 {
		return ""
	}
	return env.Errors[0].Message
}
