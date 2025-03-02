package telegram

import (
	"fmt"
	"github.com/go-faster/errors"
	"github.com/gotd/td/bin"
	"github.com/gotd/td/mtproto"
	"github.com/gotd/td/tg"
	"go.uber.org/zap"
)

type CustomClient struct {
	*Client
	StopFunc func() error
}

func NewCustomClient(appID int, appHash string, opt Options) *CustomClient {
	return &CustomClient{Client: NewClient(appID, appHash, opt)}
}

func (c *CustomClient) Stop() {
	_ = c.StopFunc()
}

type customHandler struct {
	client *Client
}

func (c *customHandler) OnSession(cfg tg.Config, s mtproto.Session) error {
	return c.client.onSession(cfg, s)
}

func (c *customHandler) OnMessage(b *bin.Buffer) error {
	updates, err := tg.DecodeUpdates(b)
	if err != nil {
		return errors.Wrap(err, "decode updates")
	}
	switch u := updates.(type) {
	case *tg.Updates:
		c.client.updateInterceptor(u.Updates...)
		return c.client.updateHandler.Handle(c.client.ctx, u)
	case *tg.UpdatesCombined:
		c.client.updateInterceptor(u.Updates...)
		return c.client.updateHandler.Handle(c.client.ctx, u)
	case *tg.UpdateShort:
		c.client.updateInterceptor(u.Update)
		return c.client.updateHandler.Handle(c.client.ctx, u)
	case *tg.UpdateShortMessage:
		return c.client.updateHandler.Handle(c.client.ctx, u)
	case *tg.UpdateShortChatMessage:
		return c.client.updateHandler.Handle(c.client.ctx, u)
	case *tg.UpdateShortSentMessage:
		return c.client.updateHandler.Handle(c.client.ctx, u)
	case *tg.UpdatesTooLong:
		return c.client.updateHandler.Handle(c.client.ctx, u)
	default:
		c.client.log.Warn("Ignoring update", zap.String("update_type", fmt.Sprintf("%T", u)))
		return c.client.updateHandler.Handle(c.client.ctx, u)
	}
}
