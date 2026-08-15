package limiter

import (
	"context"
	"errors"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type RateReader struct {
	source  buf.Reader
	reader  buf.TimeoutReader
	limiter *rate.Limiter
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewRateReader(reader buf.Reader, limiter *rate.Limiter) buf.TimeoutReader {
	timeoutReader, ok := reader.(buf.TimeoutReader)
	if !ok {
		timeoutReader = &buf.TimeoutWrapperReader{Reader: reader}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &RateReader{source: reader, reader: timeoutReader, limiter: limiter, ctx: ctx, cancel: cancel}
}

func (r *RateReader) wait(ctx context.Context, mb buf.MultiBuffer) error {
	n := int(mb.Len())
	if n == 0 || r.limiter.Limit() == rate.Inf {
		return nil
	}
	burst := r.limiter.Burst()
	if burst <= 0 {
		return errors.New("rate limiter burst must be positive")
	}
	for n > 0 {
		take := n
		if take > burst {
			take = burst
		}
		if err := r.limiter.WaitN(ctx, take); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if _, hasDeadline := ctx.Deadline(); hasDeadline {
				return context.DeadlineExceeded
			}
			return err
		}
		n -= take
	}
	return nil
}

func (r *RateReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if waitErr := r.wait(r.ctx, mb); waitErr != nil {
		buf.ReleaseMulti(mb)
		return nil, waitErr
	}
	return mb, err
}

func (r *RateReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	ctx, cancel := context.WithTimeout(r.ctx, timeout)
	defer cancel()
	mb, err := r.reader.ReadMultiBufferTimeout(timeout)
	if ctxErr := ctx.Err(); ctxErr != nil {
		buf.ReleaseMulti(mb)
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			return nil, buf.ErrReadTimeout
		}
		return nil, ctxErr
	}
	if waitErr := r.wait(ctx, mb); waitErr != nil {
		buf.ReleaseMulti(mb)
		if errors.Is(waitErr, context.DeadlineExceeded) {
			return nil, buf.ErrReadTimeout
		}
		return nil, waitErr
	}
	return mb, err
}

func (r *RateReader) Close() error {
	r.cancel()
	return common.Close(r.source)
}

func (r *RateReader) Interrupt() {
	r.cancel()
	_ = common.Interrupt(r.source)
}

type RateWriter struct {
	writer  buf.Writer
	limiter *rate.Limiter
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewRateWriter(writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	ctx, cancel := context.WithCancel(context.Background())
	return &RateWriter{
		writer:  writer,
		limiter: limiter,
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (w *RateWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	n := int(mb.Len())
	if n == 0 || w.limiter.Limit() == rate.Inf {
		return w.writer.WriteMultiBuffer(mb)
	}
	burst := w.limiter.Burst()
	if burst <= 0 {
		buf.ReleaseMulti(mb)
		return errors.New("rate limiter burst must be positive")
	}
	for n > 0 {
		take := n
		if take > burst {
			take = burst
		}
		if err := w.limiter.WaitN(w.ctx, take); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
		n -= take
	}
	return w.writer.WriteMultiBuffer(mb)
}

func (w *RateWriter) Close() error {
	w.cancel()
	return common.Close(w.writer)
}

func (w *RateWriter) Interrupt() {
	w.cancel()
	common.Interrupt(w.writer)
}
