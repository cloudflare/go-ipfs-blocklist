package blocklist

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	logging "github.com/ipfs/go-log"

	cid "github.com/ipfs/go-cid"
)

var log = logging.Logger("blocklist")

var (
	ErrNotFound = fmt.Errorf("blocklist item not found")
)

type Blocklist interface {
	Block(id cid.Cid, data BlockData) (bool, error)
	Unblock(id cid.Cid) error
	Search(id cid.Cid) (*BlocklistItem, error)
	Purge(id cid.Cid) error
	GetLogs(limit int) ([]*Action, error)
	AddLog(act *Action) error
	Contains(ctx context.Context, id cid.Cid) (bool, error)
}

// BlocklistItem packages information about why/when content was blocked, and by
// whom.
type BlocklistItem struct {
	Hash    string
	Content []string
	Reason  string
	User    string
}

func (b *BlocklistItem) MarshalBinary() ([]byte, error) {
	return json.Marshal(b)
}

func (b *BlocklistItem) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, &b)
}

// BlockData is what the "Block Content" form should be pre-populated with.
type BlockData struct {
	Blocked []string

	Content []string // Content is the URL/hash of the content to block.
	Reason  string   // Reason is an explanation for why the content is being blocked.
	User    string   // User is the email of the user that made the request.
}

// Action is an auditable action that a user requested us to perform.
type Action struct {
	Typ       string // Typ is either "block" or "unblock".
	Ids       []cid.Cid
	Reason    string
	User      string
	CreatedAt time.Time
}

func (l Action) MarshalBinary() ([]byte, error) {
	return json.Marshal(l)
}

func (l *Action) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, &l)
}

func (a *Action) String() string {
	return fmt.Sprintf("%v\t %v by %v: %v: %v", a.CreatedAt.Format(time.RFC3339), a.Typ, a.User, a.Ids, a.Reason)
}
