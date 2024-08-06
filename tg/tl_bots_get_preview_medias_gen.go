// Code generated by gotdgen, DO NOT EDIT.

package tg

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"go.uber.org/multierr"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/tdjson"
	"github.com/gotd/td/tdp"
	"github.com/gotd/td/tgerr"
)

// No-op definition for keeping imports.
var (
	_ = bin.Buffer{}
	_ = context.Background()
	_ = fmt.Stringer(nil)
	_ = strings.Builder{}
	_ = errors.Is
	_ = multierr.AppendInto
	_ = sort.Ints
	_ = tdp.Format
	_ = tgerr.Error{}
	_ = tdjson.Encoder{}
)

// BotsGetPreviewMediasRequest represents TL type `bots.getPreviewMedias#a2a5594d`.
//
// See https://core.telegram.org/method/bots.getPreviewMedias for reference.
type BotsGetPreviewMediasRequest struct {
	// Bot field of BotsGetPreviewMediasRequest.
	Bot InputUserClass
}

// BotsGetPreviewMediasRequestTypeID is TL type id of BotsGetPreviewMediasRequest.
const BotsGetPreviewMediasRequestTypeID = 0xa2a5594d

// Ensuring interfaces in compile-time for BotsGetPreviewMediasRequest.
var (
	_ bin.Encoder     = &BotsGetPreviewMediasRequest{}
	_ bin.Decoder     = &BotsGetPreviewMediasRequest{}
	_ bin.BareEncoder = &BotsGetPreviewMediasRequest{}
	_ bin.BareDecoder = &BotsGetPreviewMediasRequest{}
)

func (g *BotsGetPreviewMediasRequest) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.Bot == nil) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *BotsGetPreviewMediasRequest) String() string {
	if g == nil {
		return "BotsGetPreviewMediasRequest(nil)"
	}
	type Alias BotsGetPreviewMediasRequest
	return fmt.Sprintf("BotsGetPreviewMediasRequest%+v", Alias(*g))
}

// FillFrom fills BotsGetPreviewMediasRequest from given interface.
func (g *BotsGetPreviewMediasRequest) FillFrom(from interface {
	GetBot() (value InputUserClass)
}) {
	g.Bot = from.GetBot()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*BotsGetPreviewMediasRequest) TypeID() uint32 {
	return BotsGetPreviewMediasRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*BotsGetPreviewMediasRequest) TypeName() string {
	return "bots.getPreviewMedias"
}

// TypeInfo returns info about TL type.
func (g *BotsGetPreviewMediasRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "bots.getPreviewMedias",
		ID:   BotsGetPreviewMediasRequestTypeID,
	}
	if g == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Bot",
			SchemaName: "bot",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (g *BotsGetPreviewMediasRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode bots.getPreviewMedias#a2a5594d as nil")
	}
	b.PutID(BotsGetPreviewMediasRequestTypeID)
	return g.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (g *BotsGetPreviewMediasRequest) EncodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode bots.getPreviewMedias#a2a5594d as nil")
	}
	if g.Bot == nil {
		return fmt.Errorf("unable to encode bots.getPreviewMedias#a2a5594d: field bot is nil")
	}
	if err := g.Bot.Encode(b); err != nil {
		return fmt.Errorf("unable to encode bots.getPreviewMedias#a2a5594d: field bot: %w", err)
	}
	return nil
}

// Decode implements bin.Decoder.
func (g *BotsGetPreviewMediasRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode bots.getPreviewMedias#a2a5594d to nil")
	}
	if err := b.ConsumeID(BotsGetPreviewMediasRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode bots.getPreviewMedias#a2a5594d: %w", err)
	}
	return g.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (g *BotsGetPreviewMediasRequest) DecodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode bots.getPreviewMedias#a2a5594d to nil")
	}
	{
		value, err := DecodeInputUser(b)
		if err != nil {
			return fmt.Errorf("unable to decode bots.getPreviewMedias#a2a5594d: field bot: %w", err)
		}
		g.Bot = value
	}
	return nil
}

// GetBot returns value of Bot field.
func (g *BotsGetPreviewMediasRequest) GetBot() (value InputUserClass) {
	if g == nil {
		return
	}
	return g.Bot
}

// BotsGetPreviewMedias invokes method bots.getPreviewMedias#a2a5594d returning error if any.
//
// See https://core.telegram.org/method/bots.getPreviewMedias for reference.
func (c *Client) BotsGetPreviewMedias(ctx context.Context, bot InputUserClass) ([]BotPreviewMedia, error) {
	var result BotPreviewMediaVector

	request := &BotsGetPreviewMediasRequest{
		Bot: bot,
	}
	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return nil, err
	}
	return []BotPreviewMedia(result.Elems), nil
}
