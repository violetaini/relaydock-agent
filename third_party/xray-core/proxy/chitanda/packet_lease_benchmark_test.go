package chitanda

import (
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

type packetBenchmarkReader struct{ payload []byte }

func (r *packetBenchmarkReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return buf.MultiBuffer{ownedDatagram(r.payload)}, nil
}

func BenchmarkPacketLinkReadLease(b *testing.B) {
	for _, size := range []int{1200, 9000} {
		for _, parallel := range []bool{false, true} {
			b.Run(fmt.Sprintf("bytes=%d/parallel=%t", size, parallel), func(b *testing.B) {
				makeConn := func() *packetLinkConn {
					return newPacketLinkConn(&packetBenchmarkReader{make([]byte, size)}, nil, packetAddress("192.0.2.1:53"))
				}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				if parallel {
					b.RunParallel(func(pb *testing.PB) {
						c := makeConn()
						defer c.Close()
						output := make([]byte, size)
						for pb.Next() {
							if n, _, err := c.ReadFrom(output); err != nil || n != size {
								b.Error(n, err)
								return
							}
						}
					})
				} else {
					c := makeConn()
					defer c.Close()
					output := make([]byte, size)
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if n, _, err := c.ReadFrom(output); err != nil || n != size {
							b.Fatal(n, err)
						}
					}
				}
			})
		}
	}
}
