package xrpc

import (
	"context"
	"fmt"

	loggerpb "github.com/xtls/xray-core/app/log/command"
	handlerpb "github.com/xtls/xray-core/app/proxyman/command"
	statspb "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Clients 汇总当前用到的 gRPC 客户端。
type Clients struct {
	Connection *grpc.ClientConn
	Handler    handlerpb.HandlerServiceClient
	Logger     loggerpb.LoggerServiceClient
	Stats      statspb.StatsServiceClient
}

// 连接到运行中的 Xray API，默认使用明文连接。
func New(ctx context.Context, addr string, port uint16, dialOpts ...grpc.DialOption) (*Clients, error) {
	target := fmt.Sprintf("%s:%d", addr, port)
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	opts = append(opts, dialOpts...)

	conn, err := grpc.DialContext(ctx, target, opts...)
	if err != nil {
		return nil, err
	}

	return &Clients{
		Connection: conn,
		Handler:    handlerpb.NewHandlerServiceClient(conn),
		Logger:     loggerpb.NewLoggerServiceClient(conn),
		Stats:      statspb.NewStatsServiceClient(conn),
	}, nil
}
