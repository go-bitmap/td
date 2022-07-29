// Code generated by itergen, DO NOT EDIT.

package cached

import (
	"context"
	"sync/atomic"

	"github.com/go-faster/errors"

	"github.com/gotd/td/tg"
)

// No-op definition for keeping imports.
var _ = context.Background()

type innerAccountGetChatThemes struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.AccountThemes
}

type AccountGetChatThemes struct {
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewAccountGetChatThemes creates new AccountGetChatThemes.
func NewAccountGetChatThemes(raw *tg.Client) *AccountGetChatThemes {
	q := &AccountGetChatThemes{
		raw: raw,
	}

	return q
}

func (s *AccountGetChatThemes) store(v innerAccountGetChatThemes) {
	s.last.Store(v)
}

func (s *AccountGetChatThemes) load() (innerAccountGetChatThemes, bool) {
	v, ok := s.last.Load().(innerAccountGetChatThemes)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned AccountThemes must not be mutated.
func (s *AccountGetChatThemes) Value() *tg.AccountThemes {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *AccountGetChatThemes) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *AccountGetChatThemes) Get(ctx context.Context) (*tg.AccountThemes, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *AccountGetChatThemes) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := lastHash
	result, err := s.raw.AccountGetChatThemes(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute AccountGetChatThemes")
	}

	switch variant := result.(type) {
	case *tg.AccountThemes:
		hash := variant.Hash

		s.store(innerAccountGetChatThemes{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.AccountThemesNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}

type innerAccountGetSavedRingtones struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.AccountSavedRingtones
}

type AccountGetSavedRingtones struct {
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewAccountGetSavedRingtones creates new AccountGetSavedRingtones.
func NewAccountGetSavedRingtones(raw *tg.Client) *AccountGetSavedRingtones {
	q := &AccountGetSavedRingtones{
		raw: raw,
	}

	return q
}

func (s *AccountGetSavedRingtones) store(v innerAccountGetSavedRingtones) {
	s.last.Store(v)
}

func (s *AccountGetSavedRingtones) load() (innerAccountGetSavedRingtones, bool) {
	v, ok := s.last.Load().(innerAccountGetSavedRingtones)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned AccountSavedRingtones must not be mutated.
func (s *AccountGetSavedRingtones) Value() *tg.AccountSavedRingtones {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *AccountGetSavedRingtones) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *AccountGetSavedRingtones) Get(ctx context.Context) (*tg.AccountSavedRingtones, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *AccountGetSavedRingtones) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := lastHash
	result, err := s.raw.AccountGetSavedRingtones(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute AccountGetSavedRingtones")
	}

	switch variant := result.(type) {
	case *tg.AccountSavedRingtones:
		hash := variant.Hash

		s.store(innerAccountGetSavedRingtones{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.AccountSavedRingtonesNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}

type innerAccountGetThemes struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.AccountThemes
}

type AccountGetThemes struct {
	// Query to send.
	req *tg.AccountGetThemesRequest
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewAccountGetThemes creates new AccountGetThemes.
func NewAccountGetThemes(raw *tg.Client, initial *tg.AccountGetThemesRequest) *AccountGetThemes {
	q := &AccountGetThemes{
		req: initial,
		raw: raw,
	}

	return q
}

func (s *AccountGetThemes) store(v innerAccountGetThemes) {
	s.last.Store(v)
}

func (s *AccountGetThemes) load() (innerAccountGetThemes, bool) {
	v, ok := s.last.Load().(innerAccountGetThemes)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned AccountThemes must not be mutated.
func (s *AccountGetThemes) Value() *tg.AccountThemes {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *AccountGetThemes) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *AccountGetThemes) Get(ctx context.Context) (*tg.AccountThemes, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *AccountGetThemes) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := s.req
	req.Hash = lastHash
	result, err := s.raw.AccountGetThemes(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute AccountGetThemes")
	}

	switch variant := result.(type) {
	case *tg.AccountThemes:
		hash := variant.Hash

		s.store(innerAccountGetThemes{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.AccountThemesNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}

type innerAccountGetWallPapers struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.AccountWallPapers
}

type AccountGetWallPapers struct {
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewAccountGetWallPapers creates new AccountGetWallPapers.
func NewAccountGetWallPapers(raw *tg.Client) *AccountGetWallPapers {
	q := &AccountGetWallPapers{
		raw: raw,
	}

	return q
}

func (s *AccountGetWallPapers) store(v innerAccountGetWallPapers) {
	s.last.Store(v)
}

func (s *AccountGetWallPapers) load() (innerAccountGetWallPapers, bool) {
	v, ok := s.last.Load().(innerAccountGetWallPapers)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned AccountWallPapers must not be mutated.
func (s *AccountGetWallPapers) Value() *tg.AccountWallPapers {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *AccountGetWallPapers) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *AccountGetWallPapers) Get(ctx context.Context) (*tg.AccountWallPapers, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *AccountGetWallPapers) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := lastHash
	result, err := s.raw.AccountGetWallPapers(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute AccountGetWallPapers")
	}

	switch variant := result.(type) {
	case *tg.AccountWallPapers:
		hash := variant.Hash

		s.store(innerAccountGetWallPapers{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.AccountWallPapersNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}

type innerContactsGetContacts struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.ContactsContacts
}

type ContactsGetContacts struct {
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewContactsGetContacts creates new ContactsGetContacts.
func NewContactsGetContacts(raw *tg.Client) *ContactsGetContacts {
	q := &ContactsGetContacts{
		raw: raw,
	}

	return q
}

func (s *ContactsGetContacts) store(v innerContactsGetContacts) {
	s.last.Store(v)
}

func (s *ContactsGetContacts) load() (innerContactsGetContacts, bool) {
	v, ok := s.last.Load().(innerContactsGetContacts)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned ContactsContacts must not be mutated.
func (s *ContactsGetContacts) Value() *tg.ContactsContacts {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *ContactsGetContacts) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *ContactsGetContacts) Get(ctx context.Context) (*tg.ContactsContacts, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *ContactsGetContacts) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := lastHash
	result, err := s.raw.ContactsGetContacts(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute ContactsGetContacts")
	}

	switch variant := result.(type) {
	case *tg.ContactsContacts:
		hash := s.computeHash(variant)

		s.store(innerContactsGetContacts{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.ContactsContactsNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}

type innerMessagesGetAllStickers struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.MessagesAllStickers
}

type MessagesGetAllStickers struct {
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewMessagesGetAllStickers creates new MessagesGetAllStickers.
func NewMessagesGetAllStickers(raw *tg.Client) *MessagesGetAllStickers {
	q := &MessagesGetAllStickers{
		raw: raw,
	}

	return q
}

func (s *MessagesGetAllStickers) store(v innerMessagesGetAllStickers) {
	s.last.Store(v)
}

func (s *MessagesGetAllStickers) load() (innerMessagesGetAllStickers, bool) {
	v, ok := s.last.Load().(innerMessagesGetAllStickers)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned MessagesAllStickers must not be mutated.
func (s *MessagesGetAllStickers) Value() *tg.MessagesAllStickers {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *MessagesGetAllStickers) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *MessagesGetAllStickers) Get(ctx context.Context) (*tg.MessagesAllStickers, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *MessagesGetAllStickers) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := lastHash
	result, err := s.raw.MessagesGetAllStickers(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute MessagesGetAllStickers")
	}

	switch variant := result.(type) {
	case *tg.MessagesAllStickers:
		hash := variant.Hash

		s.store(innerMessagesGetAllStickers{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.MessagesAllStickersNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}

type innerMessagesGetAttachMenuBots struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.AttachMenuBots
}

type MessagesGetAttachMenuBots struct {
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewMessagesGetAttachMenuBots creates new MessagesGetAttachMenuBots.
func NewMessagesGetAttachMenuBots(raw *tg.Client) *MessagesGetAttachMenuBots {
	q := &MessagesGetAttachMenuBots{
		raw: raw,
	}

	return q
}

func (s *MessagesGetAttachMenuBots) store(v innerMessagesGetAttachMenuBots) {
	s.last.Store(v)
}

func (s *MessagesGetAttachMenuBots) load() (innerMessagesGetAttachMenuBots, bool) {
	v, ok := s.last.Load().(innerMessagesGetAttachMenuBots)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned AttachMenuBots must not be mutated.
func (s *MessagesGetAttachMenuBots) Value() *tg.AttachMenuBots {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *MessagesGetAttachMenuBots) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *MessagesGetAttachMenuBots) Get(ctx context.Context) (*tg.AttachMenuBots, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *MessagesGetAttachMenuBots) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := lastHash
	result, err := s.raw.MessagesGetAttachMenuBots(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute MessagesGetAttachMenuBots")
	}

	switch variant := result.(type) {
	case *tg.AttachMenuBots:
		hash := variant.Hash

		s.store(innerMessagesGetAttachMenuBots{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.AttachMenuBotsNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}

type innerMessagesGetEmojiStickers struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.MessagesAllStickers
}

type MessagesGetEmojiStickers struct {
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewMessagesGetEmojiStickers creates new MessagesGetEmojiStickers.
func NewMessagesGetEmojiStickers(raw *tg.Client) *MessagesGetEmojiStickers {
	q := &MessagesGetEmojiStickers{
		raw: raw,
	}

	return q
}

func (s *MessagesGetEmojiStickers) store(v innerMessagesGetEmojiStickers) {
	s.last.Store(v)
}

func (s *MessagesGetEmojiStickers) load() (innerMessagesGetEmojiStickers, bool) {
	v, ok := s.last.Load().(innerMessagesGetEmojiStickers)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned MessagesAllStickers must not be mutated.
func (s *MessagesGetEmojiStickers) Value() *tg.MessagesAllStickers {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *MessagesGetEmojiStickers) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *MessagesGetEmojiStickers) Get(ctx context.Context) (*tg.MessagesAllStickers, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *MessagesGetEmojiStickers) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := lastHash
	result, err := s.raw.MessagesGetEmojiStickers(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute MessagesGetEmojiStickers")
	}

	switch variant := result.(type) {
	case *tg.MessagesAllStickers:
		hash := variant.Hash

		s.store(innerMessagesGetEmojiStickers{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.MessagesAllStickersNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}

type innerMessagesGetFavedStickers struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.MessagesFavedStickers
}

type MessagesGetFavedStickers struct {
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewMessagesGetFavedStickers creates new MessagesGetFavedStickers.
func NewMessagesGetFavedStickers(raw *tg.Client) *MessagesGetFavedStickers {
	q := &MessagesGetFavedStickers{
		raw: raw,
	}

	return q
}

func (s *MessagesGetFavedStickers) store(v innerMessagesGetFavedStickers) {
	s.last.Store(v)
}

func (s *MessagesGetFavedStickers) load() (innerMessagesGetFavedStickers, bool) {
	v, ok := s.last.Load().(innerMessagesGetFavedStickers)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned MessagesFavedStickers must not be mutated.
func (s *MessagesGetFavedStickers) Value() *tg.MessagesFavedStickers {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *MessagesGetFavedStickers) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *MessagesGetFavedStickers) Get(ctx context.Context) (*tg.MessagesFavedStickers, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *MessagesGetFavedStickers) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := lastHash
	result, err := s.raw.MessagesGetFavedStickers(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute MessagesGetFavedStickers")
	}

	switch variant := result.(type) {
	case *tg.MessagesFavedStickers:
		hash := variant.Hash

		s.store(innerMessagesGetFavedStickers{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.MessagesFavedStickersNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}

type innerMessagesGetFeaturedEmojiStickers struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.MessagesFeaturedStickers
}

type MessagesGetFeaturedEmojiStickers struct {
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewMessagesGetFeaturedEmojiStickers creates new MessagesGetFeaturedEmojiStickers.
func NewMessagesGetFeaturedEmojiStickers(raw *tg.Client) *MessagesGetFeaturedEmojiStickers {
	q := &MessagesGetFeaturedEmojiStickers{
		raw: raw,
	}

	return q
}

func (s *MessagesGetFeaturedEmojiStickers) store(v innerMessagesGetFeaturedEmojiStickers) {
	s.last.Store(v)
}

func (s *MessagesGetFeaturedEmojiStickers) load() (innerMessagesGetFeaturedEmojiStickers, bool) {
	v, ok := s.last.Load().(innerMessagesGetFeaturedEmojiStickers)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned MessagesFeaturedStickers must not be mutated.
func (s *MessagesGetFeaturedEmojiStickers) Value() *tg.MessagesFeaturedStickers {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *MessagesGetFeaturedEmojiStickers) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *MessagesGetFeaturedEmojiStickers) Get(ctx context.Context) (*tg.MessagesFeaturedStickers, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *MessagesGetFeaturedEmojiStickers) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := lastHash
	result, err := s.raw.MessagesGetFeaturedEmojiStickers(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute MessagesGetFeaturedEmojiStickers")
	}

	switch variant := result.(type) {
	case *tg.MessagesFeaturedStickers:
		hash := variant.Hash

		s.store(innerMessagesGetFeaturedEmojiStickers{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.MessagesFeaturedStickersNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}

type innerMessagesGetFeaturedStickers struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.MessagesFeaturedStickers
}

type MessagesGetFeaturedStickers struct {
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewMessagesGetFeaturedStickers creates new MessagesGetFeaturedStickers.
func NewMessagesGetFeaturedStickers(raw *tg.Client) *MessagesGetFeaturedStickers {
	q := &MessagesGetFeaturedStickers{
		raw: raw,
	}

	return q
}

func (s *MessagesGetFeaturedStickers) store(v innerMessagesGetFeaturedStickers) {
	s.last.Store(v)
}

func (s *MessagesGetFeaturedStickers) load() (innerMessagesGetFeaturedStickers, bool) {
	v, ok := s.last.Load().(innerMessagesGetFeaturedStickers)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned MessagesFeaturedStickers must not be mutated.
func (s *MessagesGetFeaturedStickers) Value() *tg.MessagesFeaturedStickers {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *MessagesGetFeaturedStickers) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *MessagesGetFeaturedStickers) Get(ctx context.Context) (*tg.MessagesFeaturedStickers, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *MessagesGetFeaturedStickers) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := lastHash
	result, err := s.raw.MessagesGetFeaturedStickers(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute MessagesGetFeaturedStickers")
	}

	switch variant := result.(type) {
	case *tg.MessagesFeaturedStickers:
		hash := variant.Hash

		s.store(innerMessagesGetFeaturedStickers{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.MessagesFeaturedStickersNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}

type innerMessagesGetMaskStickers struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.MessagesAllStickers
}

type MessagesGetMaskStickers struct {
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewMessagesGetMaskStickers creates new MessagesGetMaskStickers.
func NewMessagesGetMaskStickers(raw *tg.Client) *MessagesGetMaskStickers {
	q := &MessagesGetMaskStickers{
		raw: raw,
	}

	return q
}

func (s *MessagesGetMaskStickers) store(v innerMessagesGetMaskStickers) {
	s.last.Store(v)
}

func (s *MessagesGetMaskStickers) load() (innerMessagesGetMaskStickers, bool) {
	v, ok := s.last.Load().(innerMessagesGetMaskStickers)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned MessagesAllStickers must not be mutated.
func (s *MessagesGetMaskStickers) Value() *tg.MessagesAllStickers {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *MessagesGetMaskStickers) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *MessagesGetMaskStickers) Get(ctx context.Context) (*tg.MessagesAllStickers, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *MessagesGetMaskStickers) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := lastHash
	result, err := s.raw.MessagesGetMaskStickers(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute MessagesGetMaskStickers")
	}

	switch variant := result.(type) {
	case *tg.MessagesAllStickers:
		hash := variant.Hash

		s.store(innerMessagesGetMaskStickers{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.MessagesAllStickersNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}

type innerMessagesGetRecentStickers struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.MessagesRecentStickers
}

type MessagesGetRecentStickers struct {
	// Query to send.
	req *tg.MessagesGetRecentStickersRequest
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewMessagesGetRecentStickers creates new MessagesGetRecentStickers.
func NewMessagesGetRecentStickers(raw *tg.Client, initial *tg.MessagesGetRecentStickersRequest) *MessagesGetRecentStickers {
	q := &MessagesGetRecentStickers{
		req: initial,
		raw: raw,
	}

	return q
}

func (s *MessagesGetRecentStickers) store(v innerMessagesGetRecentStickers) {
	s.last.Store(v)
}

func (s *MessagesGetRecentStickers) load() (innerMessagesGetRecentStickers, bool) {
	v, ok := s.last.Load().(innerMessagesGetRecentStickers)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned MessagesRecentStickers must not be mutated.
func (s *MessagesGetRecentStickers) Value() *tg.MessagesRecentStickers {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *MessagesGetRecentStickers) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *MessagesGetRecentStickers) Get(ctx context.Context) (*tg.MessagesRecentStickers, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *MessagesGetRecentStickers) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := s.req
	req.Hash = lastHash
	result, err := s.raw.MessagesGetRecentStickers(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute MessagesGetRecentStickers")
	}

	switch variant := result.(type) {
	case *tg.MessagesRecentStickers:
		hash := variant.Hash

		s.store(innerMessagesGetRecentStickers{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.MessagesRecentStickersNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}

type innerMessagesGetSavedGifs struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.MessagesSavedGifs
}

type MessagesGetSavedGifs struct {
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewMessagesGetSavedGifs creates new MessagesGetSavedGifs.
func NewMessagesGetSavedGifs(raw *tg.Client) *MessagesGetSavedGifs {
	q := &MessagesGetSavedGifs{
		raw: raw,
	}

	return q
}

func (s *MessagesGetSavedGifs) store(v innerMessagesGetSavedGifs) {
	s.last.Store(v)
}

func (s *MessagesGetSavedGifs) load() (innerMessagesGetSavedGifs, bool) {
	v, ok := s.last.Load().(innerMessagesGetSavedGifs)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned MessagesSavedGifs must not be mutated.
func (s *MessagesGetSavedGifs) Value() *tg.MessagesSavedGifs {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *MessagesGetSavedGifs) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *MessagesGetSavedGifs) Get(ctx context.Context) (*tg.MessagesSavedGifs, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *MessagesGetSavedGifs) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := lastHash
	result, err := s.raw.MessagesGetSavedGifs(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute MessagesGetSavedGifs")
	}

	switch variant := result.(type) {
	case *tg.MessagesSavedGifs:
		hash := variant.Hash

		s.store(innerMessagesGetSavedGifs{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.MessagesSavedGifsNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}

type innerMessagesGetStickers struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.MessagesStickers
}

type MessagesGetStickers struct {
	// Query to send.
	req *tg.MessagesGetStickersRequest
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewMessagesGetStickers creates new MessagesGetStickers.
func NewMessagesGetStickers(raw *tg.Client, initial *tg.MessagesGetStickersRequest) *MessagesGetStickers {
	q := &MessagesGetStickers{
		req: initial,
		raw: raw,
	}

	return q
}

func (s *MessagesGetStickers) store(v innerMessagesGetStickers) {
	s.last.Store(v)
}

func (s *MessagesGetStickers) load() (innerMessagesGetStickers, bool) {
	v, ok := s.last.Load().(innerMessagesGetStickers)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned MessagesStickers must not be mutated.
func (s *MessagesGetStickers) Value() *tg.MessagesStickers {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *MessagesGetStickers) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *MessagesGetStickers) Get(ctx context.Context) (*tg.MessagesStickers, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *MessagesGetStickers) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := s.req
	req.Hash = lastHash
	result, err := s.raw.MessagesGetStickers(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute MessagesGetStickers")
	}

	switch variant := result.(type) {
	case *tg.MessagesStickers:
		hash := variant.Hash

		s.store(innerMessagesGetStickers{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.MessagesStickersNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}

type innerMessagesSearchStickerSets struct {
	// Last received hash.
	hash int64
	// Last received result.
	value *tg.MessagesFoundStickerSets
}

type MessagesSearchStickerSets struct {
	// Query to send.
	req *tg.MessagesSearchStickerSetsRequest
	// Result state.
	last atomic.Value

	// Reference to RPC client to make requests.
	raw *tg.Client
}

// NewMessagesSearchStickerSets creates new MessagesSearchStickerSets.
func NewMessagesSearchStickerSets(raw *tg.Client, initial *tg.MessagesSearchStickerSetsRequest) *MessagesSearchStickerSets {
	q := &MessagesSearchStickerSets{
		req: initial,
		raw: raw,
	}

	return q
}

func (s *MessagesSearchStickerSets) store(v innerMessagesSearchStickerSets) {
	s.last.Store(v)
}

func (s *MessagesSearchStickerSets) load() (innerMessagesSearchStickerSets, bool) {
	v, ok := s.last.Load().(innerMessagesSearchStickerSets)
	return v, ok
}

// Value returns last received result.
// NB: May be nil. Returned MessagesFoundStickerSets must not be mutated.
func (s *MessagesSearchStickerSets) Value() *tg.MessagesFoundStickerSets {
	inner, _ := s.load()
	return inner.value
}

// Hash returns last received hash.
func (s *MessagesSearchStickerSets) Hash() int64 {
	inner, _ := s.load()
	return inner.hash
}

// Get updates data if needed and returns it.
func (s *MessagesSearchStickerSets) Get(ctx context.Context) (*tg.MessagesFoundStickerSets, error) {
	if _, err := s.Fetch(ctx); err != nil {
		return nil, err
	}

	return s.Value(), nil
}

// Fetch updates data if needed and returns true if data was modified.
func (s *MessagesSearchStickerSets) Fetch(ctx context.Context) (bool, error) {
	lastHash := s.Hash()

	req := s.req
	req.Hash = lastHash
	result, err := s.raw.MessagesSearchStickerSets(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "execute MessagesSearchStickerSets")
	}

	switch variant := result.(type) {
	case *tg.MessagesFoundStickerSets:
		hash := variant.Hash

		s.store(innerMessagesSearchStickerSets{
			hash:  hash,
			value: variant,
		})
		return true, nil
	case *tg.MessagesFoundStickerSetsNotModified:
		if lastHash == 0 {
			return false, errors.Errorf("got unexpected %T result", result)
		}
		return false, nil
	default:
		return false, errors.Errorf("unexpected type %T", result)
	}
}
