package logger

import (
	"context"

	"mmw-agent/internal/constants"

	loggerpb "github.com/xtls/xray-core/app/log/command"
)

// 调用 LoggerService 的 restartLogger 接口并等待完成。
func RestartLogger(ctx context.Context, client loggerpb.LoggerServiceClient) error {
	ctx, cancel := context.WithTimeout(ctx, constants.DefaultRPCShortTimeout)
	defer cancel()
	_, err := client.RestartLogger(ctx, &loggerpb.RestartLoggerRequest{})
	return err
}
