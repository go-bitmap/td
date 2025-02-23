package telegram

import (
	"github.com/gotd/td/bin"
	"github.com/gotd/td/mtproto"
	"github.com/gotd/td/tg"
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
	return c.client.handleUpdates(b)
}
