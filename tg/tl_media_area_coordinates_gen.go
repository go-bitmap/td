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

// MediaAreaCoordinates represents TL type `mediaAreaCoordinates#cfc9e002`.
// Coordinates and size of a clicable rectangular area on top of a story.
//
// See https://core.telegram.org/constructor/mediaAreaCoordinates for reference.
type MediaAreaCoordinates struct {
	// Flags field of MediaAreaCoordinates.
	Flags bin.Fields
	// The abscissa of the rectangle's center, as a percentage of the media width (0-100).
	X float64
	// The ordinate of the rectangle's center, as a percentage of the media height (0-100).
	Y float64
	// The width of the rectangle, as a percentage of the media width (0-100).
	W float64
	// The height of the rectangle, as a percentage of the media height (0-100).
	H float64
	// Clockwise rotation angle of the rectangle, in degrees (0-360).
	Rotation float64
	// Radius field of MediaAreaCoordinates.
	//
	// Use SetRadius and GetRadius helpers.
	Radius float64
}

// MediaAreaCoordinatesTypeID is TL type id of MediaAreaCoordinates.
const MediaAreaCoordinatesTypeID = 0xcfc9e002

// Ensuring interfaces in compile-time for MediaAreaCoordinates.
var (
	_ bin.Encoder     = &MediaAreaCoordinates{}
	_ bin.Decoder     = &MediaAreaCoordinates{}
	_ bin.BareEncoder = &MediaAreaCoordinates{}
	_ bin.BareDecoder = &MediaAreaCoordinates{}
)

func (m *MediaAreaCoordinates) Zero() bool {
	if m == nil {
		return true
	}
	if !(m.Flags.Zero()) {
		return false
	}
	if !(m.X == 0) {
		return false
	}
	if !(m.Y == 0) {
		return false
	}
	if !(m.W == 0) {
		return false
	}
	if !(m.H == 0) {
		return false
	}
	if !(m.Rotation == 0) {
		return false
	}
	if !(m.Radius == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (m *MediaAreaCoordinates) String() string {
	if m == nil {
		return "MediaAreaCoordinates(nil)"
	}
	type Alias MediaAreaCoordinates
	return fmt.Sprintf("MediaAreaCoordinates%+v", Alias(*m))
}

// FillFrom fills MediaAreaCoordinates from given interface.
func (m *MediaAreaCoordinates) FillFrom(from interface {
	GetX() (value float64)
	GetY() (value float64)
	GetW() (value float64)
	GetH() (value float64)
	GetRotation() (value float64)
	GetRadius() (value float64, ok bool)
}) {
	m.X = from.GetX()
	m.Y = from.GetY()
	m.W = from.GetW()
	m.H = from.GetH()
	m.Rotation = from.GetRotation()
	if val, ok := from.GetRadius(); ok {
		m.Radius = val
	}

}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*MediaAreaCoordinates) TypeID() uint32 {
	return MediaAreaCoordinatesTypeID
}

// TypeName returns name of type in TL schema.
func (*MediaAreaCoordinates) TypeName() string {
	return "mediaAreaCoordinates"
}

// TypeInfo returns info about TL type.
func (m *MediaAreaCoordinates) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "mediaAreaCoordinates",
		ID:   MediaAreaCoordinatesTypeID,
	}
	if m == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "X",
			SchemaName: "x",
		},
		{
			Name:       "Y",
			SchemaName: "y",
		},
		{
			Name:       "W",
			SchemaName: "w",
		},
		{
			Name:       "H",
			SchemaName: "h",
		},
		{
			Name:       "Rotation",
			SchemaName: "rotation",
		},
		{
			Name:       "Radius",
			SchemaName: "radius",
			Null:       !m.Flags.Has(0),
		},
	}
	return typ
}

// SetFlags sets flags for non-zero fields.
func (m *MediaAreaCoordinates) SetFlags() {
	if !(m.Radius == 0) {
		m.Flags.Set(0)
	}
}

// Encode implements bin.Encoder.
func (m *MediaAreaCoordinates) Encode(b *bin.Buffer) error {
	if m == nil {
		return fmt.Errorf("can't encode mediaAreaCoordinates#cfc9e002 as nil")
	}
	b.PutID(MediaAreaCoordinatesTypeID)
	return m.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (m *MediaAreaCoordinates) EncodeBare(b *bin.Buffer) error {
	if m == nil {
		return fmt.Errorf("can't encode mediaAreaCoordinates#cfc9e002 as nil")
	}
	m.SetFlags()
	if err := m.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode mediaAreaCoordinates#cfc9e002: field flags: %w", err)
	}
	b.PutDouble(m.X)
	b.PutDouble(m.Y)
	b.PutDouble(m.W)
	b.PutDouble(m.H)
	b.PutDouble(m.Rotation)
	if m.Flags.Has(0) {
		b.PutDouble(m.Radius)
	}
	return nil
}

// Decode implements bin.Decoder.
func (m *MediaAreaCoordinates) Decode(b *bin.Buffer) error {
	if m == nil {
		return fmt.Errorf("can't decode mediaAreaCoordinates#cfc9e002 to nil")
	}
	if err := b.ConsumeID(MediaAreaCoordinatesTypeID); err != nil {
		return fmt.Errorf("unable to decode mediaAreaCoordinates#cfc9e002: %w", err)
	}
	return m.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (m *MediaAreaCoordinates) DecodeBare(b *bin.Buffer) error {
	if m == nil {
		return fmt.Errorf("can't decode mediaAreaCoordinates#cfc9e002 to nil")
	}
	{
		if err := m.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode mediaAreaCoordinates#cfc9e002: field flags: %w", err)
		}
	}
	{
		value, err := b.Double()
		if err != nil {
			return fmt.Errorf("unable to decode mediaAreaCoordinates#cfc9e002: field x: %w", err)
		}
		m.X = value
	}
	{
		value, err := b.Double()
		if err != nil {
			return fmt.Errorf("unable to decode mediaAreaCoordinates#cfc9e002: field y: %w", err)
		}
		m.Y = value
	}
	{
		value, err := b.Double()
		if err != nil {
			return fmt.Errorf("unable to decode mediaAreaCoordinates#cfc9e002: field w: %w", err)
		}
		m.W = value
	}
	{
		value, err := b.Double()
		if err != nil {
			return fmt.Errorf("unable to decode mediaAreaCoordinates#cfc9e002: field h: %w", err)
		}
		m.H = value
	}
	{
		value, err := b.Double()
		if err != nil {
			return fmt.Errorf("unable to decode mediaAreaCoordinates#cfc9e002: field rotation: %w", err)
		}
		m.Rotation = value
	}
	if m.Flags.Has(0) {
		value, err := b.Double()
		if err != nil {
			return fmt.Errorf("unable to decode mediaAreaCoordinates#cfc9e002: field radius: %w", err)
		}
		m.Radius = value
	}
	return nil
}

// GetX returns value of X field.
func (m *MediaAreaCoordinates) GetX() (value float64) {
	if m == nil {
		return
	}
	return m.X
}

// GetY returns value of Y field.
func (m *MediaAreaCoordinates) GetY() (value float64) {
	if m == nil {
		return
	}
	return m.Y
}

// GetW returns value of W field.
func (m *MediaAreaCoordinates) GetW() (value float64) {
	if m == nil {
		return
	}
	return m.W
}

// GetH returns value of H field.
func (m *MediaAreaCoordinates) GetH() (value float64) {
	if m == nil {
		return
	}
	return m.H
}

// GetRotation returns value of Rotation field.
func (m *MediaAreaCoordinates) GetRotation() (value float64) {
	if m == nil {
		return
	}
	return m.Rotation
}

// SetRadius sets value of Radius conditional field.
func (m *MediaAreaCoordinates) SetRadius(value float64) {
	m.Flags.Set(0)
	m.Radius = value
}

// GetRadius returns value of Radius conditional field and
// boolean which is true if field was set.
func (m *MediaAreaCoordinates) GetRadius() (value float64, ok bool) {
	if m == nil {
		return
	}
	if !m.Flags.Has(0) {
		return value, false
	}
	return m.Radius, true
}
