package blocklist

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	cid "github.com/ipfs/go-cid"
	ds "github.com/ipfs/go-datastore"
	dshelp "github.com/ipfs/go-ipfs-ds-help"
	mh "github.com/multiformats/go-multihash"
)

// PgBlocklist implements a programmatic way to determine if the gateway should
// refuse to serve some content.
type PgBlocklist struct {
	client         *gorm.DB
	blocklistTable string
	datastore      ds.Batching
}

// PgBlocklistItem packages information about why/when content was blocked, and by
// whom.
type PgBlocklistItem struct {
	gorm.Model
	Hash    string `gorm:"type:varchar(100);not null"`
	Content string `gorm:"type:varchar(256);not null"`
	Reason  string
	User    string `gorm:"type:varchar(100);not null"`
}

type PgLogItem struct {
	gorm.Model
	Typ       string `gorm:"type:varchar(10)"` // Typ is either "block" or "unblock".
	RawIds    string `gorm:"column:ids"`
	Reason    string
	User      string `gorm:"type:varchar(100);not null"`
	CreatedAt time.Time
}

func NewPgBlocklist(host, port, user, password, dbname, blocklistTable string, ds ds.Batching) (*PgBlocklist, error) {
	sslmode := "require"
	// postgres is the default host on our docker-compose configuration
	if host == "postgres" {
		sslmode = "disable"
	}
	psqlconn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", host, port, user, password, dbname, sslmode)

	client, err := gorm.Open(postgres.Open(psqlconn), &gorm.Config{
		PrepareStmt: true,
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := client.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(10)

	return &PgBlocklist{client, blocklistTable, ds}, nil
}

// DB returns the underlying database connection for direct queries.
func (b *PgBlocklist) DB() *gorm.DB {
	return b.client
}

// Contains returns true if the blocklist contains the content referenced by
// `id`.
func (b PgBlocklist) Contains(ctx context.Context, id cid.Cid) (bool, error) {
	var count int64
	// converting cidv0 to cidv1, as all CID are inserted as cidv1 in the compliance database
	cidv1 := id.String()
	if id.Version() == 0 {
		hash, err := mh.FromB58String(id.String())
		if err != nil {
			return false, err
		}
		cidv1 = cid.NewCidV1(cid.DagProtobuf, hash).String()
	}
	result := b.client.
		Table(b.blocklistTable).
		Where(&PgBlocklistItem{
			Hash: cidv1,
		}).
		Count(&count)
	if err := result.Error; err != nil {
		return false, err
	}

	return count > 0, nil
}

// Block adds `id` to the list of content we won't touch. We won't serve the
// content, seed it, or even fetch it.
//
// The first return value is `true` if `id` was already blocked, in which case,
// the metadata (reason / user / time) from the first block are kept.
func (b *PgBlocklist) Block(id cid.Cid, data BlockData) (bool, error) {
	blockitem := PgBlocklistItem{
		Hash:    id.String(),
		Content: strings.Join(data.Content, "\n"),
		Reason:  data.Reason,
		User:    data.User,
	}
	if exists, err := b.Contains(context.TODO(), id); err != nil {
		return false, err
	} else if exists {
		return true, nil
	}

	result := b.client.Table(b.blocklistTable).Create(&blockitem)
	if err := result.Error; err != nil {
		return false, err
	}
	return false, nil
}

// Unblock removes `ids` from the list of blocked content. It returns the
// list of ids that were successfully unblocked.
func (b *PgBlocklist) Unblock(id cid.Cid) error {
	// Check if the blocklist entry exists.
	res, err := b.Search(id)
	if err != nil {
		return err
	}

	// Since it exists, delete it permanently instead of soft-delete.
	result := b.client.Unscoped().Delete(res)
	if err := result.Error; err != nil {
		return err
	}

	return nil
}

// Search returns metadata about why/when the content identified by `id` was
// blocked. If the content isn't blocked, ErrNotFound is returned.
func (b *PgBlocklist) Search(id cid.Cid) (*BlocklistItem, error) {
	var out PgBlocklistItem
	result := b.client.
		Table(b.blocklistTable).
		Where(&PgBlocklistItem{
			Hash: id.String(),
		}).
		First(&out)

	if err := result.Error; err != nil {
		return nil, err
	}

	return &BlocklistItem{
		Content: strings.Split(out.Content, "\n"),
		Hash:    out.Hash,
		Reason:  out.Reason,
		User:    out.User,
	}, nil
}

// Purge removes any copies of the content referenced by `id` from HBase.
func (d *PgBlocklist) Purge(id cid.Cid) error {
	return d.datastore.Delete(dshelp.CidToDsKey(id))
}

// GetLogs returns the last 100 auditable actions taken by the compliance
// dashboard, in reverse chronological order.
func (d *PgBlocklist) GetLogs(limit int) ([]*Action, error) {
	var logs []*PgLogItem
	result := d.client.
		Table("auditlog").
		Order("created_at DESC, typ").
		Limit(limit).
		Find(&logs)

	if err := result.Error; err != nil {
		return nil, err
	}

	// Unsplit ids
	acts := make([]*Action, len(logs))
	for i, log := range logs {
		rawIds := strings.Split(log.RawIds, ";")
		ids := make([]cid.Cid, 0, len(rawIds))
		for i, r := range rawIds {
			id, err := cid.Parse(r)
			if err != nil {
				return nil, err
			}
			ids[i] = id
		}
		acts[i] = &Action{
			Typ:       log.Typ,
			Ids:       ids,
			Reason:    log.Reason,
			User:      log.User,
			CreatedAt: log.CreatedAt,
		}
	}

	return acts, nil
}

// Log saves a record that `act` took place.
func (d *PgBlocklist) AddLog(act *Action) error {
	if act.Typ != "block" && act.Typ != "unblock" {
		return fmt.Errorf("unexpected action type: '%v'", act.Typ)
	}
	log.Info(act.String())

	rawIds := make([]string, 0, len(act.Ids))
	for i, id := range act.Ids {
		rawIds[i] = id.String()
	}

	result := d.client.
		Table("auditlog").
		Create(&PgLogItem{
			Typ:    act.Typ,
			RawIds: strings.Join(rawIds, ";"),
			Reason: act.Reason,
			User:   act.User,
		})
	if err := result.Error; err != nil {
		return err
	}
	return nil
}
