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

// MessagesGetChatInviteImportersRequest represents TL type `messages.getChatInviteImporters#df04dd4e`.
// Get info about the users that joined the chat using a specific chat invite
//
// See https://core.telegram.org/method/messages.getChatInviteImporters for reference.
type MessagesGetChatInviteImportersRequest struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields
	// If set, only returns info about users with pending join requests »¹
	//
	// Links:
	//  1) https://core.telegram.org/api/invites#join-requests
	Requested bool
	// Chat
	Peer InputPeerClass
	// Invite link
	//
	// Use SetLink and GetLink helpers.
	Link string
	// Search for a user in the pending join requests »¹ list: only available when the
	// requested flag is set, cannot be used together with a specific link.
	//
	// Links:
	//  1) https://core.telegram.org/api/invites#join-requests
	//
	// Use SetQ and GetQ helpers.
	Q string
	// Offsets for pagination, for more info click here¹
	//
	// Links:
	//  1) https://core.telegram.org/api/offsets
	OffsetDate int
	// User ID for pagination¹
	//
	// Links:
	//  1) https://core.telegram.org/api/offsets
	OffsetUser InputUserClass
	// Maximum number of results to return, see pagination¹
	//
	// Links:
	//  1) https://core.telegram.org/api/offsets
	Limit int
}

// MessagesGetChatInviteImportersRequestTypeID is TL type id of MessagesGetChatInviteImportersRequest.
const MessagesGetChatInviteImportersRequestTypeID = 0xdf04dd4e

// Ensuring interfaces in compile-time for MessagesGetChatInviteImportersRequest.
var (
	_ bin.Encoder     = &MessagesGetChatInviteImportersRequest{}
	_ bin.Decoder     = &MessagesGetChatInviteImportersRequest{}
	_ bin.BareEncoder = &MessagesGetChatInviteImportersRequest{}
	_ bin.BareDecoder = &MessagesGetChatInviteImportersRequest{}
)

func (g *MessagesGetChatInviteImportersRequest) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.Flags.Zero()) {
		return false
	}
	if !(g.Requested == false) {
		return false
	}
	if !(g.Peer == nil) {
		return false
	}
	if !(g.Link == "") {
		return false
	}
	if !(g.Q == "") {
		return false
	}
	if !(g.OffsetDate == 0) {
		return false
	}
	if !(g.OffsetUser == nil) {
		return false
	}
	if !(g.Limit == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *MessagesGetChatInviteImportersRequest) String() string {
	if g == nil {
		return "MessagesGetChatInviteImportersRequest(nil)"
	}
	type Alias MessagesGetChatInviteImportersRequest
	return fmt.Sprintf("MessagesGetChatInviteImportersRequest%+v", Alias(*g))
}

// FillFrom fills MessagesGetChatInviteImportersRequest from given interface.
func (g *MessagesGetChatInviteImportersRequest) FillFrom(from interface {
	GetRequested() (value bool)
	GetPeer() (value InputPeerClass)
	GetLink() (value string, ok bool)
	GetQ() (value string, ok bool)
	GetOffsetDate() (value int)
	GetOffsetUser() (value InputUserClass)
	GetLimit() (value int)
}) {
	g.Requested = from.GetRequested()
	g.Peer = from.GetPeer()
	if val, ok := from.GetLink(); ok {
		g.Link = val
	}

	if val, ok := from.GetQ(); ok {
		g.Q = val
	}

	g.OffsetDate = from.GetOffsetDate()
	g.OffsetUser = from.GetOffsetUser()
	g.Limit = from.GetLimit()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*MessagesGetChatInviteImportersRequest) TypeID() uint32 {
	return MessagesGetChatInviteImportersRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*MessagesGetChatInviteImportersRequest) TypeName() string {
	return "messages.getChatInviteImporters"
}

// TypeInfo returns info about TL type.
func (g *MessagesGetChatInviteImportersRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "messages.getChatInviteImporters",
		ID:   MessagesGetChatInviteImportersRequestTypeID,
	}
	if g == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Requested",
			SchemaName: "requested",
			Null:       !g.Flags.Has(0),
		},
		{
			Name:       "Peer",
			SchemaName: "peer",
		},
		{
			Name:       "Link",
			SchemaName: "link",
			Null:       !g.Flags.Has(1),
		},
		{
			Name:       "Q",
			SchemaName: "q",
			Null:       !g.Flags.Has(2),
		},
		{
			Name:       "OffsetDate",
			SchemaName: "offset_date",
		},
		{
			Name:       "OffsetUser",
			SchemaName: "offset_user",
		},
		{
			Name:       "Limit",
			SchemaName: "limit",
		},
	}
	return typ
}

// SetFlags sets flags for non-zero fields.
func (g *MessagesGetChatInviteImportersRequest) SetFlags() {
	if !(g.Requested == false) {
		g.Flags.Set(0)
	}
	if !(g.Link == "") {
		g.Flags.Set(1)
	}
	if !(g.Q == "") {
		g.Flags.Set(2)
	}
}

// Encode implements bin.Encoder.
func (g *MessagesGetChatInviteImportersRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode messages.getChatInviteImporters#df04dd4e as nil")
	}
	b.PutID(MessagesGetChatInviteImportersRequestTypeID)
	return g.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (g *MessagesGetChatInviteImportersRequest) EncodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode messages.getChatInviteImporters#df04dd4e as nil")
	}
	g.SetFlags()
	if err := g.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.getChatInviteImporters#df04dd4e: field flags: %w", err)
	}
	if g.Peer == nil {
		return fmt.Errorf("unable to encode messages.getChatInviteImporters#df04dd4e: field peer is nil")
	}
	if err := g.Peer.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.getChatInviteImporters#df04dd4e: field peer: %w", err)
	}
	if g.Flags.Has(1) {
		b.PutString(g.Link)
	}
	if g.Flags.Has(2) {
		b.PutString(g.Q)
	}
	b.PutInt(g.OffsetDate)
	if g.OffsetUser == nil {
		return fmt.Errorf("unable to encode messages.getChatInviteImporters#df04dd4e: field offset_user is nil")
	}
	if err := g.OffsetUser.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.getChatInviteImporters#df04dd4e: field offset_user: %w", err)
	}
	b.PutInt(g.Limit)
	return nil
}

// Decode implements bin.Decoder.
func (g *MessagesGetChatInviteImportersRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode messages.getChatInviteImporters#df04dd4e to nil")
	}
	if err := b.ConsumeID(MessagesGetChatInviteImportersRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode messages.getChatInviteImporters#df04dd4e: %w", err)
	}
	return g.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (g *MessagesGetChatInviteImportersRequest) DecodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode messages.getChatInviteImporters#df04dd4e to nil")
	}
	{
		if err := g.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode messages.getChatInviteImporters#df04dd4e: field flags: %w", err)
		}
	}
	g.Requested = g.Flags.Has(0)
	{
		value, err := DecodeInputPeer(b)
		if err != nil {
			return fmt.Errorf("unable to decode messages.getChatInviteImporters#df04dd4e: field peer: %w", err)
		}
		g.Peer = value
	}
	if g.Flags.Has(1) {
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode messages.getChatInviteImporters#df04dd4e: field link: %w", err)
		}
		g.Link = value
	}
	if g.Flags.Has(2) {
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode messages.getChatInviteImporters#df04dd4e: field q: %w", err)
		}
		g.Q = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode messages.getChatInviteImporters#df04dd4e: field offset_date: %w", err)
		}
		g.OffsetDate = value
	}
	{
		value, err := DecodeInputUser(b)
		if err != nil {
			return fmt.Errorf("unable to decode messages.getChatInviteImporters#df04dd4e: field offset_user: %w", err)
		}
		g.OffsetUser = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode messages.getChatInviteImporters#df04dd4e: field limit: %w", err)
		}
		g.Limit = value
	}
	return nil
}

// SetRequested sets value of Requested conditional field.
func (g *MessagesGetChatInviteImportersRequest) SetRequested(value bool) {
	if value {
		g.Flags.Set(0)
		g.Requested = true
	} else {
		g.Flags.Unset(0)
		g.Requested = false
	}
}

// GetRequested returns value of Requested conditional field.
func (g *MessagesGetChatInviteImportersRequest) GetRequested() (value bool) {
	if g == nil {
		return
	}
	return g.Flags.Has(0)
}

// GetPeer returns value of Peer field.
func (g *MessagesGetChatInviteImportersRequest) GetPeer() (value InputPeerClass) {
	if g == nil {
		return
	}
	return g.Peer
}

// SetLink sets value of Link conditional field.
func (g *MessagesGetChatInviteImportersRequest) SetLink(value string) {
	g.Flags.Set(1)
	g.Link = value
}

// GetLink returns value of Link conditional field and
// boolean which is true if field was set.
func (g *MessagesGetChatInviteImportersRequest) GetLink() (value string, ok bool) {
	if g == nil {
		return
	}
	if !g.Flags.Has(1) {
		return value, false
	}
	return g.Link, true
}

// SetQ sets value of Q conditional field.
func (g *MessagesGetChatInviteImportersRequest) SetQ(value string) {
	g.Flags.Set(2)
	g.Q = value
}

// GetQ returns value of Q conditional field and
// boolean which is true if field was set.
func (g *MessagesGetChatInviteImportersRequest) GetQ() (value string, ok bool) {
	if g == nil {
		return
	}
	if !g.Flags.Has(2) {
		return value, false
	}
	return g.Q, true
}

// GetOffsetDate returns value of OffsetDate field.
func (g *MessagesGetChatInviteImportersRequest) GetOffsetDate() (value int) {
	if g == nil {
		return
	}
	return g.OffsetDate
}

// GetOffsetUser returns value of OffsetUser field.
func (g *MessagesGetChatInviteImportersRequest) GetOffsetUser() (value InputUserClass) {
	if g == nil {
		return
	}
	return g.OffsetUser
}

// GetLimit returns value of Limit field.
func (g *MessagesGetChatInviteImportersRequest) GetLimit() (value int) {
	if g == nil {
		return
	}
	return g.Limit
}

// MessagesGetChatInviteImporters invokes method messages.getChatInviteImporters#df04dd4e returning error if any.
// Get info about the users that joined the chat using a specific chat invite
//
// Possible errors:
//
//	400 CHANNEL_PRIVATE: You haven't joined this channel/supergroup.
//	400 CHAT_ADMIN_REQUIRED: You must be an admin in this chat to do this.
//	403 CHAT_WRITE_FORBIDDEN: You can't write in this chat.
//	400 INVITE_HASH_EXPIRED: The invite link has expired.
//	500 INVITE_HASH_UNSYNC:
//	400 PEER_ID_INVALID: The provided peer id is invalid.
//	400 SEARCH_WITH_LINK_NOT_SUPPORTED: You cannot provide a search query and an invite link at the same time.
//
// See https://core.telegram.org/method/messages.getChatInviteImporters for reference.
func (c *Client) MessagesGetChatInviteImporters(ctx context.Context, request *MessagesGetChatInviteImportersRequest) (*MessagesChatInviteImporters, error) {
	var result MessagesChatInviteImporters

	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
