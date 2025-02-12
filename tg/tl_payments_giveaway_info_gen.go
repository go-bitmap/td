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

// PaymentsGiveawayInfo represents TL type `payments.giveawayInfo#4367daa0`.
// Contains info about an ongoing giveaway¹.
// If neither the participating, joined_too_early_date, admin_disallowed_chat_id or
// disallowed_country flags are set, the user is not currently participating in the
// giveaway but could participate by joining all the channels specified in the
// messageMediaGiveaway¹.channels field.
//
// Links:
//  1. https://core.telegram.org/api/giveaways
//  2. https://core.telegram.org/constructor/messageMediaGiveaway
//
// See https://core.telegram.org/constructor/payments.giveawayInfo for reference.
type PaymentsGiveawayInfo struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields
	// The current user is participating in the giveaway.
	Participating bool
	// If set, the giveaway has ended and the results are being prepared.
	PreparingResults bool
	// When was the giveaway started
	StartDate int
	// The current user can't participate in the giveaway, because they were already a member
	// of the channel when the giveaway started, and the only_new_subscribers was set when
	// starting the giveaway.
	//
	// Use SetJoinedTooEarlyDate and GetJoinedTooEarlyDate helpers.
	JoinedTooEarlyDate int
	// If set, the current user can't participate in the giveaway, because they are an
	// administrator in one of the channels (ID specified in this flag) that created the
	// giveaway.
	//
	// Use SetAdminDisallowedChatID and GetAdminDisallowedChatID helpers.
	AdminDisallowedChatID int64
	// If set, the current user can't participate in this giveaway, because their phone
	// number is from the specified disallowed country (specified as a two-letter ISO 3166-1
	// alpha-2 country code).
	//
	// Use SetDisallowedCountry and GetDisallowedCountry helpers.
	DisallowedCountry string
}

// PaymentsGiveawayInfoTypeID is TL type id of PaymentsGiveawayInfo.
const PaymentsGiveawayInfoTypeID = 0x4367daa0

// construct implements constructor of PaymentsGiveawayInfoClass.
func (g PaymentsGiveawayInfo) construct() PaymentsGiveawayInfoClass { return &g }

// Ensuring interfaces in compile-time for PaymentsGiveawayInfo.
var (
	_ bin.Encoder     = &PaymentsGiveawayInfo{}
	_ bin.Decoder     = &PaymentsGiveawayInfo{}
	_ bin.BareEncoder = &PaymentsGiveawayInfo{}
	_ bin.BareDecoder = &PaymentsGiveawayInfo{}

	_ PaymentsGiveawayInfoClass = &PaymentsGiveawayInfo{}
)

func (g *PaymentsGiveawayInfo) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.Flags.Zero()) {
		return false
	}
	if !(g.Participating == false) {
		return false
	}
	if !(g.PreparingResults == false) {
		return false
	}
	if !(g.StartDate == 0) {
		return false
	}
	if !(g.JoinedTooEarlyDate == 0) {
		return false
	}
	if !(g.AdminDisallowedChatID == 0) {
		return false
	}
	if !(g.DisallowedCountry == "") {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *PaymentsGiveawayInfo) String() string {
	if g == nil {
		return "PaymentsGiveawayInfo(nil)"
	}
	type Alias PaymentsGiveawayInfo
	return fmt.Sprintf("PaymentsGiveawayInfo%+v", Alias(*g))
}

// FillFrom fills PaymentsGiveawayInfo from given interface.
func (g *PaymentsGiveawayInfo) FillFrom(from interface {
	GetParticipating() (value bool)
	GetPreparingResults() (value bool)
	GetStartDate() (value int)
	GetJoinedTooEarlyDate() (value int, ok bool)
	GetAdminDisallowedChatID() (value int64, ok bool)
	GetDisallowedCountry() (value string, ok bool)
}) {
	g.Participating = from.GetParticipating()
	g.PreparingResults = from.GetPreparingResults()
	g.StartDate = from.GetStartDate()
	if val, ok := from.GetJoinedTooEarlyDate(); ok {
		g.JoinedTooEarlyDate = val
	}

	if val, ok := from.GetAdminDisallowedChatID(); ok {
		g.AdminDisallowedChatID = val
	}

	if val, ok := from.GetDisallowedCountry(); ok {
		g.DisallowedCountry = val
	}

}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*PaymentsGiveawayInfo) TypeID() uint32 {
	return PaymentsGiveawayInfoTypeID
}

// TypeName returns name of type in TL schema.
func (*PaymentsGiveawayInfo) TypeName() string {
	return "payments.giveawayInfo"
}

// TypeInfo returns info about TL type.
func (g *PaymentsGiveawayInfo) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "payments.giveawayInfo",
		ID:   PaymentsGiveawayInfoTypeID,
	}
	if g == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Participating",
			SchemaName: "participating",
			Null:       !g.Flags.Has(0),
		},
		{
			Name:       "PreparingResults",
			SchemaName: "preparing_results",
			Null:       !g.Flags.Has(3),
		},
		{
			Name:       "StartDate",
			SchemaName: "start_date",
		},
		{
			Name:       "JoinedTooEarlyDate",
			SchemaName: "joined_too_early_date",
			Null:       !g.Flags.Has(1),
		},
		{
			Name:       "AdminDisallowedChatID",
			SchemaName: "admin_disallowed_chat_id",
			Null:       !g.Flags.Has(2),
		},
		{
			Name:       "DisallowedCountry",
			SchemaName: "disallowed_country",
			Null:       !g.Flags.Has(4),
		},
	}
	return typ
}

// SetFlags sets flags for non-zero fields.
func (g *PaymentsGiveawayInfo) SetFlags() {
	if !(g.Participating == false) {
		g.Flags.Set(0)
	}
	if !(g.PreparingResults == false) {
		g.Flags.Set(3)
	}
	if !(g.JoinedTooEarlyDate == 0) {
		g.Flags.Set(1)
	}
	if !(g.AdminDisallowedChatID == 0) {
		g.Flags.Set(2)
	}
	if !(g.DisallowedCountry == "") {
		g.Flags.Set(4)
	}
}

// Encode implements bin.Encoder.
func (g *PaymentsGiveawayInfo) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode payments.giveawayInfo#4367daa0 as nil")
	}
	b.PutID(PaymentsGiveawayInfoTypeID)
	return g.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (g *PaymentsGiveawayInfo) EncodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode payments.giveawayInfo#4367daa0 as nil")
	}
	g.SetFlags()
	if err := g.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode payments.giveawayInfo#4367daa0: field flags: %w", err)
	}
	b.PutInt(g.StartDate)
	if g.Flags.Has(1) {
		b.PutInt(g.JoinedTooEarlyDate)
	}
	if g.Flags.Has(2) {
		b.PutLong(g.AdminDisallowedChatID)
	}
	if g.Flags.Has(4) {
		b.PutString(g.DisallowedCountry)
	}
	return nil
}

// Decode implements bin.Decoder.
func (g *PaymentsGiveawayInfo) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode payments.giveawayInfo#4367daa0 to nil")
	}
	if err := b.ConsumeID(PaymentsGiveawayInfoTypeID); err != nil {
		return fmt.Errorf("unable to decode payments.giveawayInfo#4367daa0: %w", err)
	}
	return g.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (g *PaymentsGiveawayInfo) DecodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode payments.giveawayInfo#4367daa0 to nil")
	}
	{
		if err := g.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode payments.giveawayInfo#4367daa0: field flags: %w", err)
		}
	}
	g.Participating = g.Flags.Has(0)
	g.PreparingResults = g.Flags.Has(3)
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode payments.giveawayInfo#4367daa0: field start_date: %w", err)
		}
		g.StartDate = value
	}
	if g.Flags.Has(1) {
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode payments.giveawayInfo#4367daa0: field joined_too_early_date: %w", err)
		}
		g.JoinedTooEarlyDate = value
	}
	if g.Flags.Has(2) {
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode payments.giveawayInfo#4367daa0: field admin_disallowed_chat_id: %w", err)
		}
		g.AdminDisallowedChatID = value
	}
	if g.Flags.Has(4) {
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode payments.giveawayInfo#4367daa0: field disallowed_country: %w", err)
		}
		g.DisallowedCountry = value
	}
	return nil
}

// SetParticipating sets value of Participating conditional field.
func (g *PaymentsGiveawayInfo) SetParticipating(value bool) {
	if value {
		g.Flags.Set(0)
		g.Participating = true
	} else {
		g.Flags.Unset(0)
		g.Participating = false
	}
}

// GetParticipating returns value of Participating conditional field.
func (g *PaymentsGiveawayInfo) GetParticipating() (value bool) {
	if g == nil {
		return
	}
	return g.Flags.Has(0)
}

// SetPreparingResults sets value of PreparingResults conditional field.
func (g *PaymentsGiveawayInfo) SetPreparingResults(value bool) {
	if value {
		g.Flags.Set(3)
		g.PreparingResults = true
	} else {
		g.Flags.Unset(3)
		g.PreparingResults = false
	}
}

// GetPreparingResults returns value of PreparingResults conditional field.
func (g *PaymentsGiveawayInfo) GetPreparingResults() (value bool) {
	if g == nil {
		return
	}
	return g.Flags.Has(3)
}

// GetStartDate returns value of StartDate field.
func (g *PaymentsGiveawayInfo) GetStartDate() (value int) {
	if g == nil {
		return
	}
	return g.StartDate
}

// SetJoinedTooEarlyDate sets value of JoinedTooEarlyDate conditional field.
func (g *PaymentsGiveawayInfo) SetJoinedTooEarlyDate(value int) {
	g.Flags.Set(1)
	g.JoinedTooEarlyDate = value
}

// GetJoinedTooEarlyDate returns value of JoinedTooEarlyDate conditional field and
// boolean which is true if field was set.
func (g *PaymentsGiveawayInfo) GetJoinedTooEarlyDate() (value int, ok bool) {
	if g == nil {
		return
	}
	if !g.Flags.Has(1) {
		return value, false
	}
	return g.JoinedTooEarlyDate, true
}

// SetAdminDisallowedChatID sets value of AdminDisallowedChatID conditional field.
func (g *PaymentsGiveawayInfo) SetAdminDisallowedChatID(value int64) {
	g.Flags.Set(2)
	g.AdminDisallowedChatID = value
}

// GetAdminDisallowedChatID returns value of AdminDisallowedChatID conditional field and
// boolean which is true if field was set.
func (g *PaymentsGiveawayInfo) GetAdminDisallowedChatID() (value int64, ok bool) {
	if g == nil {
		return
	}
	if !g.Flags.Has(2) {
		return value, false
	}
	return g.AdminDisallowedChatID, true
}

// SetDisallowedCountry sets value of DisallowedCountry conditional field.
func (g *PaymentsGiveawayInfo) SetDisallowedCountry(value string) {
	g.Flags.Set(4)
	g.DisallowedCountry = value
}

// GetDisallowedCountry returns value of DisallowedCountry conditional field and
// boolean which is true if field was set.
func (g *PaymentsGiveawayInfo) GetDisallowedCountry() (value string, ok bool) {
	if g == nil {
		return
	}
	if !g.Flags.Has(4) {
		return value, false
	}
	return g.DisallowedCountry, true
}

// PaymentsGiveawayInfoResults represents TL type `payments.giveawayInfoResults#e175e66f`.
// A giveaway¹ has ended.
//
// Links:
//  1. https://core.telegram.org/api/giveaways
//
// See https://core.telegram.org/constructor/payments.giveawayInfoResults for reference.
type PaymentsGiveawayInfoResults struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields
	// Whether we're one of the winners of this giveaway.
	Winner bool
	// Whether the giveaway was canceled and was fully refunded.
	Refunded bool
	// Start date of the giveaway
	StartDate int
	// If we're one of the winners of this giveaway, contains the Premium gift code¹, see
	// here »² for more info on the full giveaway flow.
	//
	// Links:
	//  1) https://core.telegram.org/api/links#premium-giftcode-links
	//  2) https://core.telegram.org/api/giveaways
	//
	// Use SetGiftCodeSlug and GetGiftCodeSlug helpers.
	GiftCodeSlug string
	// If we're one of the winners of this Telegram Star giveaway¹, the number Telegram
	// Stars² we won.
	//
	// Links:
	//  1) https://core.telegram.org/api/giveaways#star-giveaways
	//  2) https://core.telegram.org/api/stars
	//
	// Use SetStarsPrize and GetStarsPrize helpers.
	StarsPrize int64
	// End date of the giveaway. May be bigger than the end date specified in parameters of
	// the giveaway.
	FinishDate int
	// Number of winners in the giveaway
	WinnersCount int
	// Number of winners, which activated their gift codes¹.
	//
	// Links:
	//  1) https://core.telegram.org/api/links#premium-giftcode-links
	//
	// Use SetActivatedCount and GetActivatedCount helpers.
	ActivatedCount int
}

// PaymentsGiveawayInfoResultsTypeID is TL type id of PaymentsGiveawayInfoResults.
const PaymentsGiveawayInfoResultsTypeID = 0xe175e66f

// construct implements constructor of PaymentsGiveawayInfoClass.
func (g PaymentsGiveawayInfoResults) construct() PaymentsGiveawayInfoClass { return &g }

// Ensuring interfaces in compile-time for PaymentsGiveawayInfoResults.
var (
	_ bin.Encoder     = &PaymentsGiveawayInfoResults{}
	_ bin.Decoder     = &PaymentsGiveawayInfoResults{}
	_ bin.BareEncoder = &PaymentsGiveawayInfoResults{}
	_ bin.BareDecoder = &PaymentsGiveawayInfoResults{}

	_ PaymentsGiveawayInfoClass = &PaymentsGiveawayInfoResults{}
)

func (g *PaymentsGiveawayInfoResults) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.Flags.Zero()) {
		return false
	}
	if !(g.Winner == false) {
		return false
	}
	if !(g.Refunded == false) {
		return false
	}
	if !(g.StartDate == 0) {
		return false
	}
	if !(g.GiftCodeSlug == "") {
		return false
	}
	if !(g.StarsPrize == 0) {
		return false
	}
	if !(g.FinishDate == 0) {
		return false
	}
	if !(g.WinnersCount == 0) {
		return false
	}
	if !(g.ActivatedCount == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *PaymentsGiveawayInfoResults) String() string {
	if g == nil {
		return "PaymentsGiveawayInfoResults(nil)"
	}
	type Alias PaymentsGiveawayInfoResults
	return fmt.Sprintf("PaymentsGiveawayInfoResults%+v", Alias(*g))
}

// FillFrom fills PaymentsGiveawayInfoResults from given interface.
func (g *PaymentsGiveawayInfoResults) FillFrom(from interface {
	GetWinner() (value bool)
	GetRefunded() (value bool)
	GetStartDate() (value int)
	GetGiftCodeSlug() (value string, ok bool)
	GetStarsPrize() (value int64, ok bool)
	GetFinishDate() (value int)
	GetWinnersCount() (value int)
	GetActivatedCount() (value int, ok bool)
}) {
	g.Winner = from.GetWinner()
	g.Refunded = from.GetRefunded()
	g.StartDate = from.GetStartDate()
	if val, ok := from.GetGiftCodeSlug(); ok {
		g.GiftCodeSlug = val
	}

	if val, ok := from.GetStarsPrize(); ok {
		g.StarsPrize = val
	}

	g.FinishDate = from.GetFinishDate()
	g.WinnersCount = from.GetWinnersCount()
	if val, ok := from.GetActivatedCount(); ok {
		g.ActivatedCount = val
	}

}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*PaymentsGiveawayInfoResults) TypeID() uint32 {
	return PaymentsGiveawayInfoResultsTypeID
}

// TypeName returns name of type in TL schema.
func (*PaymentsGiveawayInfoResults) TypeName() string {
	return "payments.giveawayInfoResults"
}

// TypeInfo returns info about TL type.
func (g *PaymentsGiveawayInfoResults) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "payments.giveawayInfoResults",
		ID:   PaymentsGiveawayInfoResultsTypeID,
	}
	if g == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Winner",
			SchemaName: "winner",
			Null:       !g.Flags.Has(0),
		},
		{
			Name:       "Refunded",
			SchemaName: "refunded",
			Null:       !g.Flags.Has(1),
		},
		{
			Name:       "StartDate",
			SchemaName: "start_date",
		},
		{
			Name:       "GiftCodeSlug",
			SchemaName: "gift_code_slug",
			Null:       !g.Flags.Has(3),
		},
		{
			Name:       "StarsPrize",
			SchemaName: "stars_prize",
			Null:       !g.Flags.Has(4),
		},
		{
			Name:       "FinishDate",
			SchemaName: "finish_date",
		},
		{
			Name:       "WinnersCount",
			SchemaName: "winners_count",
		},
		{
			Name:       "ActivatedCount",
			SchemaName: "activated_count",
			Null:       !g.Flags.Has(2),
		},
	}
	return typ
}

// SetFlags sets flags for non-zero fields.
func (g *PaymentsGiveawayInfoResults) SetFlags() {
	if !(g.Winner == false) {
		g.Flags.Set(0)
	}
	if !(g.Refunded == false) {
		g.Flags.Set(1)
	}
	if !(g.GiftCodeSlug == "") {
		g.Flags.Set(3)
	}
	if !(g.StarsPrize == 0) {
		g.Flags.Set(4)
	}
	if !(g.ActivatedCount == 0) {
		g.Flags.Set(2)
	}
}

// Encode implements bin.Encoder.
func (g *PaymentsGiveawayInfoResults) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode payments.giveawayInfoResults#e175e66f as nil")
	}
	b.PutID(PaymentsGiveawayInfoResultsTypeID)
	return g.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (g *PaymentsGiveawayInfoResults) EncodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode payments.giveawayInfoResults#e175e66f as nil")
	}
	g.SetFlags()
	if err := g.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode payments.giveawayInfoResults#e175e66f: field flags: %w", err)
	}
	b.PutInt(g.StartDate)
	if g.Flags.Has(3) {
		b.PutString(g.GiftCodeSlug)
	}
	if g.Flags.Has(4) {
		b.PutLong(g.StarsPrize)
	}
	b.PutInt(g.FinishDate)
	b.PutInt(g.WinnersCount)
	if g.Flags.Has(2) {
		b.PutInt(g.ActivatedCount)
	}
	return nil
}

// Decode implements bin.Decoder.
func (g *PaymentsGiveawayInfoResults) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode payments.giveawayInfoResults#e175e66f to nil")
	}
	if err := b.ConsumeID(PaymentsGiveawayInfoResultsTypeID); err != nil {
		return fmt.Errorf("unable to decode payments.giveawayInfoResults#e175e66f: %w", err)
	}
	return g.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (g *PaymentsGiveawayInfoResults) DecodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode payments.giveawayInfoResults#e175e66f to nil")
	}
	{
		if err := g.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode payments.giveawayInfoResults#e175e66f: field flags: %w", err)
		}
	}
	g.Winner = g.Flags.Has(0)
	g.Refunded = g.Flags.Has(1)
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode payments.giveawayInfoResults#e175e66f: field start_date: %w", err)
		}
		g.StartDate = value
	}
	if g.Flags.Has(3) {
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode payments.giveawayInfoResults#e175e66f: field gift_code_slug: %w", err)
		}
		g.GiftCodeSlug = value
	}
	if g.Flags.Has(4) {
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode payments.giveawayInfoResults#e175e66f: field stars_prize: %w", err)
		}
		g.StarsPrize = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode payments.giveawayInfoResults#e175e66f: field finish_date: %w", err)
		}
		g.FinishDate = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode payments.giveawayInfoResults#e175e66f: field winners_count: %w", err)
		}
		g.WinnersCount = value
	}
	if g.Flags.Has(2) {
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode payments.giveawayInfoResults#e175e66f: field activated_count: %w", err)
		}
		g.ActivatedCount = value
	}
	return nil
}

// SetWinner sets value of Winner conditional field.
func (g *PaymentsGiveawayInfoResults) SetWinner(value bool) {
	if value {
		g.Flags.Set(0)
		g.Winner = true
	} else {
		g.Flags.Unset(0)
		g.Winner = false
	}
}

// GetWinner returns value of Winner conditional field.
func (g *PaymentsGiveawayInfoResults) GetWinner() (value bool) {
	if g == nil {
		return
	}
	return g.Flags.Has(0)
}

// SetRefunded sets value of Refunded conditional field.
func (g *PaymentsGiveawayInfoResults) SetRefunded(value bool) {
	if value {
		g.Flags.Set(1)
		g.Refunded = true
	} else {
		g.Flags.Unset(1)
		g.Refunded = false
	}
}

// GetRefunded returns value of Refunded conditional field.
func (g *PaymentsGiveawayInfoResults) GetRefunded() (value bool) {
	if g == nil {
		return
	}
	return g.Flags.Has(1)
}

// GetStartDate returns value of StartDate field.
func (g *PaymentsGiveawayInfoResults) GetStartDate() (value int) {
	if g == nil {
		return
	}
	return g.StartDate
}

// SetGiftCodeSlug sets value of GiftCodeSlug conditional field.
func (g *PaymentsGiveawayInfoResults) SetGiftCodeSlug(value string) {
	g.Flags.Set(3)
	g.GiftCodeSlug = value
}

// GetGiftCodeSlug returns value of GiftCodeSlug conditional field and
// boolean which is true if field was set.
func (g *PaymentsGiveawayInfoResults) GetGiftCodeSlug() (value string, ok bool) {
	if g == nil {
		return
	}
	if !g.Flags.Has(3) {
		return value, false
	}
	return g.GiftCodeSlug, true
}

// SetStarsPrize sets value of StarsPrize conditional field.
func (g *PaymentsGiveawayInfoResults) SetStarsPrize(value int64) {
	g.Flags.Set(4)
	g.StarsPrize = value
}

// GetStarsPrize returns value of StarsPrize conditional field and
// boolean which is true if field was set.
func (g *PaymentsGiveawayInfoResults) GetStarsPrize() (value int64, ok bool) {
	if g == nil {
		return
	}
	if !g.Flags.Has(4) {
		return value, false
	}
	return g.StarsPrize, true
}

// GetFinishDate returns value of FinishDate field.
func (g *PaymentsGiveawayInfoResults) GetFinishDate() (value int) {
	if g == nil {
		return
	}
	return g.FinishDate
}

// GetWinnersCount returns value of WinnersCount field.
func (g *PaymentsGiveawayInfoResults) GetWinnersCount() (value int) {
	if g == nil {
		return
	}
	return g.WinnersCount
}

// SetActivatedCount sets value of ActivatedCount conditional field.
func (g *PaymentsGiveawayInfoResults) SetActivatedCount(value int) {
	g.Flags.Set(2)
	g.ActivatedCount = value
}

// GetActivatedCount returns value of ActivatedCount conditional field and
// boolean which is true if field was set.
func (g *PaymentsGiveawayInfoResults) GetActivatedCount() (value int, ok bool) {
	if g == nil {
		return
	}
	if !g.Flags.Has(2) {
		return value, false
	}
	return g.ActivatedCount, true
}

// PaymentsGiveawayInfoClassName is schema name of PaymentsGiveawayInfoClass.
const PaymentsGiveawayInfoClassName = "payments.GiveawayInfo"

// PaymentsGiveawayInfoClass represents payments.GiveawayInfo generic type.
//
// See https://core.telegram.org/type/payments.GiveawayInfo for reference.
//
// Constructors:
//   - [PaymentsGiveawayInfo]
//   - [PaymentsGiveawayInfoResults]
//
// Example:
//
//	g, err := tg.DecodePaymentsGiveawayInfo(buf)
//	if err != nil {
//	    panic(err)
//	}
//	switch v := g.(type) {
//	case *tg.PaymentsGiveawayInfo: // payments.giveawayInfo#4367daa0
//	case *tg.PaymentsGiveawayInfoResults: // payments.giveawayInfoResults#e175e66f
//	default: panic(v)
//	}
type PaymentsGiveawayInfoClass interface {
	bin.Encoder
	bin.Decoder
	bin.BareEncoder
	bin.BareDecoder
	construct() PaymentsGiveawayInfoClass

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

	// When was the giveaway started
	GetStartDate() (value int)
}

// DecodePaymentsGiveawayInfo implements binary de-serialization for PaymentsGiveawayInfoClass.
func DecodePaymentsGiveawayInfo(buf *bin.Buffer) (PaymentsGiveawayInfoClass, error) {
	id, err := buf.PeekID()
	if err != nil {
		return nil, err
	}
	switch id {
	case PaymentsGiveawayInfoTypeID:
		// Decoding payments.giveawayInfo#4367daa0.
		v := PaymentsGiveawayInfo{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode PaymentsGiveawayInfoClass: %w", err)
		}
		return &v, nil
	case PaymentsGiveawayInfoResultsTypeID:
		// Decoding payments.giveawayInfoResults#e175e66f.
		v := PaymentsGiveawayInfoResults{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode PaymentsGiveawayInfoClass: %w", err)
		}
		return &v, nil
	default:
		return nil, fmt.Errorf("unable to decode PaymentsGiveawayInfoClass: %w", bin.NewUnexpectedID(id))
	}
}

// PaymentsGiveawayInfo boxes the PaymentsGiveawayInfoClass providing a helper.
type PaymentsGiveawayInfoBox struct {
	GiveawayInfo PaymentsGiveawayInfoClass
}

// Decode implements bin.Decoder for PaymentsGiveawayInfoBox.
func (b *PaymentsGiveawayInfoBox) Decode(buf *bin.Buffer) error {
	if b == nil {
		return fmt.Errorf("unable to decode PaymentsGiveawayInfoBox to nil")
	}
	v, err := DecodePaymentsGiveawayInfo(buf)
	if err != nil {
		return fmt.Errorf("unable to decode boxed value: %w", err)
	}
	b.GiveawayInfo = v
	return nil
}

// Encode implements bin.Encode for PaymentsGiveawayInfoBox.
func (b *PaymentsGiveawayInfoBox) Encode(buf *bin.Buffer) error {
	if b == nil || b.GiveawayInfo == nil {
		return fmt.Errorf("unable to encode PaymentsGiveawayInfoClass as nil")
	}
	return b.GiveawayInfo.Encode(buf)
}
