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

// Dialog represents TL type `dialog#d58a08c6`.
// Chat
//
// See https://core.telegram.org/constructor/dialog for reference.
type Dialog struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields
	// Is the dialog pinned
	Pinned bool
	// Whether the chat was manually marked as unread
	UnreadMark bool
	// The chat
	Peer PeerClass
	// The latest message ID
	TopMessage int
	// Position up to which all incoming messages are read.
	ReadInboxMaxID int
	// Position up to which all outgoing messages are read.
	ReadOutboxMaxID int
	// Number of unread messages
	UnreadCount int
	// Number of unread mentions¹
	//
	// Links:
	//  1) https://core.telegram.org/api/mentions
	UnreadMentionsCount int
	// Number of unread reactions to messages you sent
	UnreadReactionsCount int
	// Notification settings
	NotifySettings PeerNotifySettings
	// PTS¹
	//
	// Links:
	//  1) https://core.telegram.org/api/updates
	//
	// Use SetPts and GetPts helpers.
	Pts int
	// Message draft
	//
	// Use SetDraft and GetDraft helpers.
	Draft DraftMessageClass
	// Peer folder ID, for more info click here¹
	//
	// Links:
	//  1) https://core.telegram.org/api/folders#peer-folders
	//
	// Use SetFolderID and GetFolderID helpers.
	FolderID int
	//
	//
	// Use SetTTLPeriod and GetTTLPeriod helpers.
	TTLPeriod int
}

// DialogTypeID is TL type id of Dialog.
const DialogTypeID = 0xd58a08c6

// construct implements constructor of DialogClass.
func (d Dialog) construct() DialogClass { return &d }

// Ensuring interfaces in compile-time for Dialog.
var (
	_ bin.Encoder     = &Dialog{}
	_ bin.Decoder     = &Dialog{}
	_ bin.BareEncoder = &Dialog{}
	_ bin.BareDecoder = &Dialog{}

	_ DialogClass = &Dialog{}
)

func (d *Dialog) Zero() bool {
	if d == nil {
		return true
	}
	if !(d.Flags.Zero()) {
		return false
	}
	if !(d.Pinned == false) {
		return false
	}
	if !(d.UnreadMark == false) {
		return false
	}
	if !(d.Peer == nil) {
		return false
	}
	if !(d.TopMessage == 0) {
		return false
	}
	if !(d.ReadInboxMaxID == 0) {
		return false
	}
	if !(d.ReadOutboxMaxID == 0) {
		return false
	}
	if !(d.UnreadCount == 0) {
		return false
	}
	if !(d.UnreadMentionsCount == 0) {
		return false
	}
	if !(d.UnreadReactionsCount == 0) {
		return false
	}
	if !(d.NotifySettings.Zero()) {
		return false
	}
	if !(d.Pts == 0) {
		return false
	}
	if !(d.Draft == nil) {
		return false
	}
	if !(d.FolderID == 0) {
		return false
	}
	if !(d.TTLPeriod == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (d *Dialog) String() string {
	if d == nil {
		return "Dialog(nil)"
	}
	type Alias Dialog
	return fmt.Sprintf("Dialog%+v", Alias(*d))
}

// FillFrom fills Dialog from given interface.
func (d *Dialog) FillFrom(from interface {
	GetPinned() (value bool)
	GetUnreadMark() (value bool)
	GetPeer() (value PeerClass)
	GetTopMessage() (value int)
	GetReadInboxMaxID() (value int)
	GetReadOutboxMaxID() (value int)
	GetUnreadCount() (value int)
	GetUnreadMentionsCount() (value int)
	GetUnreadReactionsCount() (value int)
	GetNotifySettings() (value PeerNotifySettings)
	GetPts() (value int, ok bool)
	GetDraft() (value DraftMessageClass, ok bool)
	GetFolderID() (value int, ok bool)
	GetTTLPeriod() (value int, ok bool)
}) {
	d.Pinned = from.GetPinned()
	d.UnreadMark = from.GetUnreadMark()
	d.Peer = from.GetPeer()
	d.TopMessage = from.GetTopMessage()
	d.ReadInboxMaxID = from.GetReadInboxMaxID()
	d.ReadOutboxMaxID = from.GetReadOutboxMaxID()
	d.UnreadCount = from.GetUnreadCount()
	d.UnreadMentionsCount = from.GetUnreadMentionsCount()
	d.UnreadReactionsCount = from.GetUnreadReactionsCount()
	d.NotifySettings = from.GetNotifySettings()
	if val, ok := from.GetPts(); ok {
		d.Pts = val
	}

	if val, ok := from.GetDraft(); ok {
		d.Draft = val
	}

	if val, ok := from.GetFolderID(); ok {
		d.FolderID = val
	}

	if val, ok := from.GetTTLPeriod(); ok {
		d.TTLPeriod = val
	}

}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*Dialog) TypeID() uint32 {
	return DialogTypeID
}

// TypeName returns name of type in TL schema.
func (*Dialog) TypeName() string {
	return "dialog"
}

// TypeInfo returns info about TL type.
func (d *Dialog) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "dialog",
		ID:   DialogTypeID,
	}
	if d == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Pinned",
			SchemaName: "pinned",
			Null:       !d.Flags.Has(2),
		},
		{
			Name:       "UnreadMark",
			SchemaName: "unread_mark",
			Null:       !d.Flags.Has(3),
		},
		{
			Name:       "Peer",
			SchemaName: "peer",
		},
		{
			Name:       "TopMessage",
			SchemaName: "top_message",
		},
		{
			Name:       "ReadInboxMaxID",
			SchemaName: "read_inbox_max_id",
		},
		{
			Name:       "ReadOutboxMaxID",
			SchemaName: "read_outbox_max_id",
		},
		{
			Name:       "UnreadCount",
			SchemaName: "unread_count",
		},
		{
			Name:       "UnreadMentionsCount",
			SchemaName: "unread_mentions_count",
		},
		{
			Name:       "UnreadReactionsCount",
			SchemaName: "unread_reactions_count",
		},
		{
			Name:       "NotifySettings",
			SchemaName: "notify_settings",
		},
		{
			Name:       "Pts",
			SchemaName: "pts",
			Null:       !d.Flags.Has(0),
		},
		{
			Name:       "Draft",
			SchemaName: "draft",
			Null:       !d.Flags.Has(1),
		},
		{
			Name:       "FolderID",
			SchemaName: "folder_id",
			Null:       !d.Flags.Has(4),
		},
		{
			Name:       "TTLPeriod",
			SchemaName: "ttl_period",
			Null:       !d.Flags.Has(5),
		},
	}
	return typ
}

// SetFlags sets flags for non-zero fields.
func (d *Dialog) SetFlags() {
	if !(d.Pinned == false) {
		d.Flags.Set(2)
	}
	if !(d.UnreadMark == false) {
		d.Flags.Set(3)
	}
	if !(d.Pts == 0) {
		d.Flags.Set(0)
	}
	if !(d.Draft == nil) {
		d.Flags.Set(1)
	}
	if !(d.FolderID == 0) {
		d.Flags.Set(4)
	}
	if !(d.TTLPeriod == 0) {
		d.Flags.Set(5)
	}
}

// Encode implements bin.Encoder.
func (d *Dialog) Encode(b *bin.Buffer) error {
	if d == nil {
		return fmt.Errorf("can't encode dialog#d58a08c6 as nil")
	}
	b.PutID(DialogTypeID)
	return d.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (d *Dialog) EncodeBare(b *bin.Buffer) error {
	if d == nil {
		return fmt.Errorf("can't encode dialog#d58a08c6 as nil")
	}
	d.SetFlags()
	if err := d.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode dialog#d58a08c6: field flags: %w", err)
	}
	if d.Peer == nil {
		return fmt.Errorf("unable to encode dialog#d58a08c6: field peer is nil")
	}
	if err := d.Peer.Encode(b); err != nil {
		return fmt.Errorf("unable to encode dialog#d58a08c6: field peer: %w", err)
	}
	b.PutInt(d.TopMessage)
	b.PutInt(d.ReadInboxMaxID)
	b.PutInt(d.ReadOutboxMaxID)
	b.PutInt(d.UnreadCount)
	b.PutInt(d.UnreadMentionsCount)
	b.PutInt(d.UnreadReactionsCount)
	if err := d.NotifySettings.Encode(b); err != nil {
		return fmt.Errorf("unable to encode dialog#d58a08c6: field notify_settings: %w", err)
	}
	if d.Flags.Has(0) {
		b.PutInt(d.Pts)
	}
	if d.Flags.Has(1) {
		if d.Draft == nil {
			return fmt.Errorf("unable to encode dialog#d58a08c6: field draft is nil")
		}
		if err := d.Draft.Encode(b); err != nil {
			return fmt.Errorf("unable to encode dialog#d58a08c6: field draft: %w", err)
		}
	}
	if d.Flags.Has(4) {
		b.PutInt(d.FolderID)
	}
	if d.Flags.Has(5) {
		b.PutInt(d.TTLPeriod)
	}
	return nil
}

// Decode implements bin.Decoder.
func (d *Dialog) Decode(b *bin.Buffer) error {
	if d == nil {
		return fmt.Errorf("can't decode dialog#d58a08c6 to nil")
	}
	if err := b.ConsumeID(DialogTypeID); err != nil {
		return fmt.Errorf("unable to decode dialog#d58a08c6: %w", err)
	}
	return d.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (d *Dialog) DecodeBare(b *bin.Buffer) error {
	if d == nil {
		return fmt.Errorf("can't decode dialog#d58a08c6 to nil")
	}
	{
		if err := d.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode dialog#d58a08c6: field flags: %w", err)
		}
	}
	d.Pinned = d.Flags.Has(2)
	d.UnreadMark = d.Flags.Has(3)
	{
		value, err := DecodePeer(b)
		if err != nil {
			return fmt.Errorf("unable to decode dialog#d58a08c6: field peer: %w", err)
		}
		d.Peer = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode dialog#d58a08c6: field top_message: %w", err)
		}
		d.TopMessage = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode dialog#d58a08c6: field read_inbox_max_id: %w", err)
		}
		d.ReadInboxMaxID = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode dialog#d58a08c6: field read_outbox_max_id: %w", err)
		}
		d.ReadOutboxMaxID = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode dialog#d58a08c6: field unread_count: %w", err)
		}
		d.UnreadCount = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode dialog#d58a08c6: field unread_mentions_count: %w", err)
		}
		d.UnreadMentionsCount = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode dialog#d58a08c6: field unread_reactions_count: %w", err)
		}
		d.UnreadReactionsCount = value
	}
	{
		if err := d.NotifySettings.Decode(b); err != nil {
			return fmt.Errorf("unable to decode dialog#d58a08c6: field notify_settings: %w", err)
		}
	}
	if d.Flags.Has(0) {
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode dialog#d58a08c6: field pts: %w", err)
		}
		d.Pts = value
	}
	if d.Flags.Has(1) {
		value, err := DecodeDraftMessage(b)
		if err != nil {
			return fmt.Errorf("unable to decode dialog#d58a08c6: field draft: %w", err)
		}
		d.Draft = value
	}
	if d.Flags.Has(4) {
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode dialog#d58a08c6: field folder_id: %w", err)
		}
		d.FolderID = value
	}
	if d.Flags.Has(5) {
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode dialog#d58a08c6: field ttl_period: %w", err)
		}
		d.TTLPeriod = value
	}
	return nil
}

// SetPinned sets value of Pinned conditional field.
func (d *Dialog) SetPinned(value bool) {
	if value {
		d.Flags.Set(2)
		d.Pinned = true
	} else {
		d.Flags.Unset(2)
		d.Pinned = false
	}
}

// GetPinned returns value of Pinned conditional field.
func (d *Dialog) GetPinned() (value bool) {
	if d == nil {
		return
	}
	return d.Flags.Has(2)
}

// SetUnreadMark sets value of UnreadMark conditional field.
func (d *Dialog) SetUnreadMark(value bool) {
	if value {
		d.Flags.Set(3)
		d.UnreadMark = true
	} else {
		d.Flags.Unset(3)
		d.UnreadMark = false
	}
}

// GetUnreadMark returns value of UnreadMark conditional field.
func (d *Dialog) GetUnreadMark() (value bool) {
	if d == nil {
		return
	}
	return d.Flags.Has(3)
}

// GetPeer returns value of Peer field.
func (d *Dialog) GetPeer() (value PeerClass) {
	if d == nil {
		return
	}
	return d.Peer
}

// GetTopMessage returns value of TopMessage field.
func (d *Dialog) GetTopMessage() (value int) {
	if d == nil {
		return
	}
	return d.TopMessage
}

// GetReadInboxMaxID returns value of ReadInboxMaxID field.
func (d *Dialog) GetReadInboxMaxID() (value int) {
	if d == nil {
		return
	}
	return d.ReadInboxMaxID
}

// GetReadOutboxMaxID returns value of ReadOutboxMaxID field.
func (d *Dialog) GetReadOutboxMaxID() (value int) {
	if d == nil {
		return
	}
	return d.ReadOutboxMaxID
}

// GetUnreadCount returns value of UnreadCount field.
func (d *Dialog) GetUnreadCount() (value int) {
	if d == nil {
		return
	}
	return d.UnreadCount
}

// GetUnreadMentionsCount returns value of UnreadMentionsCount field.
func (d *Dialog) GetUnreadMentionsCount() (value int) {
	if d == nil {
		return
	}
	return d.UnreadMentionsCount
}

// GetUnreadReactionsCount returns value of UnreadReactionsCount field.
func (d *Dialog) GetUnreadReactionsCount() (value int) {
	if d == nil {
		return
	}
	return d.UnreadReactionsCount
}

// GetNotifySettings returns value of NotifySettings field.
func (d *Dialog) GetNotifySettings() (value PeerNotifySettings) {
	if d == nil {
		return
	}
	return d.NotifySettings
}

// SetPts sets value of Pts conditional field.
func (d *Dialog) SetPts(value int) {
	d.Flags.Set(0)
	d.Pts = value
}

// GetPts returns value of Pts conditional field and
// boolean which is true if field was set.
func (d *Dialog) GetPts() (value int, ok bool) {
	if d == nil {
		return
	}
	if !d.Flags.Has(0) {
		return value, false
	}
	return d.Pts, true
}

// SetDraft sets value of Draft conditional field.
func (d *Dialog) SetDraft(value DraftMessageClass) {
	d.Flags.Set(1)
	d.Draft = value
}

// GetDraft returns value of Draft conditional field and
// boolean which is true if field was set.
func (d *Dialog) GetDraft() (value DraftMessageClass, ok bool) {
	if d == nil {
		return
	}
	if !d.Flags.Has(1) {
		return value, false
	}
	return d.Draft, true
}

// SetFolderID sets value of FolderID conditional field.
func (d *Dialog) SetFolderID(value int) {
	d.Flags.Set(4)
	d.FolderID = value
}

// GetFolderID returns value of FolderID conditional field and
// boolean which is true if field was set.
func (d *Dialog) GetFolderID() (value int, ok bool) {
	if d == nil {
		return
	}
	if !d.Flags.Has(4) {
		return value, false
	}
	return d.FolderID, true
}

// SetTTLPeriod sets value of TTLPeriod conditional field.
func (d *Dialog) SetTTLPeriod(value int) {
	d.Flags.Set(5)
	d.TTLPeriod = value
}

// GetTTLPeriod returns value of TTLPeriod conditional field and
// boolean which is true if field was set.
func (d *Dialog) GetTTLPeriod() (value int, ok bool) {
	if d == nil {
		return
	}
	if !d.Flags.Has(5) {
		return value, false
	}
	return d.TTLPeriod, true
}

// DialogFolder represents TL type `dialogFolder#71bd134c`.
// Dialog in folder
//
// See https://core.telegram.org/constructor/dialogFolder for reference.
type DialogFolder struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields
	// Is this folder pinned
	Pinned bool
	// The folder
	Folder Folder
	// Peer in folder
	Peer PeerClass
	// Latest message ID of dialog
	TopMessage int
	// Number of unread muted peers in folder
	UnreadMutedPeersCount int
	// Number of unread unmuted peers in folder
	UnreadUnmutedPeersCount int
	// Number of unread messages from muted peers in folder
	UnreadMutedMessagesCount int
	// Number of unread messages from unmuted peers in folder
	UnreadUnmutedMessagesCount int
}

// DialogFolderTypeID is TL type id of DialogFolder.
const DialogFolderTypeID = 0x71bd134c

// construct implements constructor of DialogClass.
func (d DialogFolder) construct() DialogClass { return &d }

// Ensuring interfaces in compile-time for DialogFolder.
var (
	_ bin.Encoder     = &DialogFolder{}
	_ bin.Decoder     = &DialogFolder{}
	_ bin.BareEncoder = &DialogFolder{}
	_ bin.BareDecoder = &DialogFolder{}

	_ DialogClass = &DialogFolder{}
)

func (d *DialogFolder) Zero() bool {
	if d == nil {
		return true
	}
	if !(d.Flags.Zero()) {
		return false
	}
	if !(d.Pinned == false) {
		return false
	}
	if !(d.Folder.Zero()) {
		return false
	}
	if !(d.Peer == nil) {
		return false
	}
	if !(d.TopMessage == 0) {
		return false
	}
	if !(d.UnreadMutedPeersCount == 0) {
		return false
	}
	if !(d.UnreadUnmutedPeersCount == 0) {
		return false
	}
	if !(d.UnreadMutedMessagesCount == 0) {
		return false
	}
	if !(d.UnreadUnmutedMessagesCount == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (d *DialogFolder) String() string {
	if d == nil {
		return "DialogFolder(nil)"
	}
	type Alias DialogFolder
	return fmt.Sprintf("DialogFolder%+v", Alias(*d))
}

// FillFrom fills DialogFolder from given interface.
func (d *DialogFolder) FillFrom(from interface {
	GetPinned() (value bool)
	GetFolder() (value Folder)
	GetPeer() (value PeerClass)
	GetTopMessage() (value int)
	GetUnreadMutedPeersCount() (value int)
	GetUnreadUnmutedPeersCount() (value int)
	GetUnreadMutedMessagesCount() (value int)
	GetUnreadUnmutedMessagesCount() (value int)
}) {
	d.Pinned = from.GetPinned()
	d.Folder = from.GetFolder()
	d.Peer = from.GetPeer()
	d.TopMessage = from.GetTopMessage()
	d.UnreadMutedPeersCount = from.GetUnreadMutedPeersCount()
	d.UnreadUnmutedPeersCount = from.GetUnreadUnmutedPeersCount()
	d.UnreadMutedMessagesCount = from.GetUnreadMutedMessagesCount()
	d.UnreadUnmutedMessagesCount = from.GetUnreadUnmutedMessagesCount()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*DialogFolder) TypeID() uint32 {
	return DialogFolderTypeID
}

// TypeName returns name of type in TL schema.
func (*DialogFolder) TypeName() string {
	return "dialogFolder"
}

// TypeInfo returns info about TL type.
func (d *DialogFolder) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "dialogFolder",
		ID:   DialogFolderTypeID,
	}
	if d == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Pinned",
			SchemaName: "pinned",
			Null:       !d.Flags.Has(2),
		},
		{
			Name:       "Folder",
			SchemaName: "folder",
		},
		{
			Name:       "Peer",
			SchemaName: "peer",
		},
		{
			Name:       "TopMessage",
			SchemaName: "top_message",
		},
		{
			Name:       "UnreadMutedPeersCount",
			SchemaName: "unread_muted_peers_count",
		},
		{
			Name:       "UnreadUnmutedPeersCount",
			SchemaName: "unread_unmuted_peers_count",
		},
		{
			Name:       "UnreadMutedMessagesCount",
			SchemaName: "unread_muted_messages_count",
		},
		{
			Name:       "UnreadUnmutedMessagesCount",
			SchemaName: "unread_unmuted_messages_count",
		},
	}
	return typ
}

// SetFlags sets flags for non-zero fields.
func (d *DialogFolder) SetFlags() {
	if !(d.Pinned == false) {
		d.Flags.Set(2)
	}
}

// Encode implements bin.Encoder.
func (d *DialogFolder) Encode(b *bin.Buffer) error {
	if d == nil {
		return fmt.Errorf("can't encode dialogFolder#71bd134c as nil")
	}
	b.PutID(DialogFolderTypeID)
	return d.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (d *DialogFolder) EncodeBare(b *bin.Buffer) error {
	if d == nil {
		return fmt.Errorf("can't encode dialogFolder#71bd134c as nil")
	}
	d.SetFlags()
	if err := d.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode dialogFolder#71bd134c: field flags: %w", err)
	}
	if err := d.Folder.Encode(b); err != nil {
		return fmt.Errorf("unable to encode dialogFolder#71bd134c: field folder: %w", err)
	}
	if d.Peer == nil {
		return fmt.Errorf("unable to encode dialogFolder#71bd134c: field peer is nil")
	}
	if err := d.Peer.Encode(b); err != nil {
		return fmt.Errorf("unable to encode dialogFolder#71bd134c: field peer: %w", err)
	}
	b.PutInt(d.TopMessage)
	b.PutInt(d.UnreadMutedPeersCount)
	b.PutInt(d.UnreadUnmutedPeersCount)
	b.PutInt(d.UnreadMutedMessagesCount)
	b.PutInt(d.UnreadUnmutedMessagesCount)
	return nil
}

// Decode implements bin.Decoder.
func (d *DialogFolder) Decode(b *bin.Buffer) error {
	if d == nil {
		return fmt.Errorf("can't decode dialogFolder#71bd134c to nil")
	}
	if err := b.ConsumeID(DialogFolderTypeID); err != nil {
		return fmt.Errorf("unable to decode dialogFolder#71bd134c: %w", err)
	}
	return d.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (d *DialogFolder) DecodeBare(b *bin.Buffer) error {
	if d == nil {
		return fmt.Errorf("can't decode dialogFolder#71bd134c to nil")
	}
	{
		if err := d.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode dialogFolder#71bd134c: field flags: %w", err)
		}
	}
	d.Pinned = d.Flags.Has(2)
	{
		if err := d.Folder.Decode(b); err != nil {
			return fmt.Errorf("unable to decode dialogFolder#71bd134c: field folder: %w", err)
		}
	}
	{
		value, err := DecodePeer(b)
		if err != nil {
			return fmt.Errorf("unable to decode dialogFolder#71bd134c: field peer: %w", err)
		}
		d.Peer = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode dialogFolder#71bd134c: field top_message: %w", err)
		}
		d.TopMessage = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode dialogFolder#71bd134c: field unread_muted_peers_count: %w", err)
		}
		d.UnreadMutedPeersCount = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode dialogFolder#71bd134c: field unread_unmuted_peers_count: %w", err)
		}
		d.UnreadUnmutedPeersCount = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode dialogFolder#71bd134c: field unread_muted_messages_count: %w", err)
		}
		d.UnreadMutedMessagesCount = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode dialogFolder#71bd134c: field unread_unmuted_messages_count: %w", err)
		}
		d.UnreadUnmutedMessagesCount = value
	}
	return nil
}

// SetPinned sets value of Pinned conditional field.
func (d *DialogFolder) SetPinned(value bool) {
	if value {
		d.Flags.Set(2)
		d.Pinned = true
	} else {
		d.Flags.Unset(2)
		d.Pinned = false
	}
}

// GetPinned returns value of Pinned conditional field.
func (d *DialogFolder) GetPinned() (value bool) {
	if d == nil {
		return
	}
	return d.Flags.Has(2)
}

// GetFolder returns value of Folder field.
func (d *DialogFolder) GetFolder() (value Folder) {
	if d == nil {
		return
	}
	return d.Folder
}

// GetPeer returns value of Peer field.
func (d *DialogFolder) GetPeer() (value PeerClass) {
	if d == nil {
		return
	}
	return d.Peer
}

// GetTopMessage returns value of TopMessage field.
func (d *DialogFolder) GetTopMessage() (value int) {
	if d == nil {
		return
	}
	return d.TopMessage
}

// GetUnreadMutedPeersCount returns value of UnreadMutedPeersCount field.
func (d *DialogFolder) GetUnreadMutedPeersCount() (value int) {
	if d == nil {
		return
	}
	return d.UnreadMutedPeersCount
}

// GetUnreadUnmutedPeersCount returns value of UnreadUnmutedPeersCount field.
func (d *DialogFolder) GetUnreadUnmutedPeersCount() (value int) {
	if d == nil {
		return
	}
	return d.UnreadUnmutedPeersCount
}

// GetUnreadMutedMessagesCount returns value of UnreadMutedMessagesCount field.
func (d *DialogFolder) GetUnreadMutedMessagesCount() (value int) {
	if d == nil {
		return
	}
	return d.UnreadMutedMessagesCount
}

// GetUnreadUnmutedMessagesCount returns value of UnreadUnmutedMessagesCount field.
func (d *DialogFolder) GetUnreadUnmutedMessagesCount() (value int) {
	if d == nil {
		return
	}
	return d.UnreadUnmutedMessagesCount
}

// DialogClassName is schema name of DialogClass.
const DialogClassName = "Dialog"

// DialogClass represents Dialog generic type.
//
// See https://core.telegram.org/type/Dialog for reference.
//
// Example:
//
//	g, err := tg.DecodeDialog(buf)
//	if err != nil {
//	    panic(err)
//	}
//	switch v := g.(type) {
//	case *tg.Dialog: // dialog#d58a08c6
//	case *tg.DialogFolder: // dialogFolder#71bd134c
//	default: panic(v)
//	}
type DialogClass interface {
	bin.Encoder
	bin.Decoder
	bin.BareEncoder
	bin.BareDecoder
	construct() DialogClass

	// TypeID returns type id in TL schema.
	//
	// See https://core.telegram.org/mtproto/TL-tl#remarks.
	TypeID() uint32
	// TypeName returns name of type in TL schema.
	TypeName() string
	// String implements fmt.Stringer.
	String() string
	// Zero returns true if current object has a zero value.
	Zero() bool

	// Is the dialog pinned
	GetPinned() (value bool)

	// The chat
	GetPeer() (value PeerClass)

	// The latest message ID
	GetTopMessage() (value int)
}

// AsInputDialogPeerFolder tries to map Dialog to InputDialogPeerFolder.
func (d *Dialog) AsInputDialogPeerFolder() *InputDialogPeerFolder {
	value := new(InputDialogPeerFolder)
	if fieldValue, ok := d.GetFolderID(); ok {
		value.FolderID = fieldValue
	}

	return value
}

// DecodeDialog implements binary de-serialization for DialogClass.
func DecodeDialog(buf *bin.Buffer) (DialogClass, error) {
	id, err := buf.PeekID()
	if err != nil {
		return nil, err
	}
	switch id {
	case DialogTypeID:
		// Decoding dialog#d58a08c6.
		v := Dialog{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode DialogClass: %w", err)
		}
		return &v, nil
	case DialogFolderTypeID:
		// Decoding dialogFolder#71bd134c.
		v := DialogFolder{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode DialogClass: %w", err)
		}
		return &v, nil
	default:
		return nil, fmt.Errorf("unable to decode DialogClass: %w", bin.NewUnexpectedID(id))
	}
}

// Dialog boxes the DialogClass providing a helper.
type DialogBox struct {
	Dialog DialogClass
}

// Decode implements bin.Decoder for DialogBox.
func (b *DialogBox) Decode(buf *bin.Buffer) error {
	if b == nil {
		return fmt.Errorf("unable to decode DialogBox to nil")
	}
	v, err := DecodeDialog(buf)
	if err != nil {
		return fmt.Errorf("unable to decode boxed value: %w", err)
	}
	b.Dialog = v
	return nil
}

// Encode implements bin.Encode for DialogBox.
func (b *DialogBox) Encode(buf *bin.Buffer) error {
	if b == nil || b.Dialog == nil {
		return fmt.Errorf("unable to encode DialogClass as nil")
	}
	return b.Dialog.Encode(buf)
}
