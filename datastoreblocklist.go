package blocklist

import (
	"context"
	"fmt"
	"time"

	cid "github.com/ipfs/go-cid"
	ds "github.com/ipfs/go-datastore"
	dsns "github.com/ipfs/go-datastore/namespace"
	dsq "github.com/ipfs/go-datastore/query"
	dshelp "github.com/ipfs/go-ipfs-ds-help"
	mh "github.com/multiformats/go-multihash"
)

// SafemodePrefix namespaces safemodestore datastores
var SafemodePrefix = ds.NewKey("safemode")

// Blocklist namespaces safemodestore datastores
var BlocklistPrefix = ds.NewKey("blocklist")

// Audit namespaces safemodestore datastores
var AuditPrefix = ds.NewKey("audit")

// PgBlocklist implements a programmatic way to determine if the gateway should
// refuse to serve some content.
type DatastoreBlocklist struct {
	datastore     ds.Batching
	auditstore    ds.Batching
	safemodestore ds.Batching
}

func NewDatastoreBlocklist(d ds.Batching) DatastoreBlocklist {
	dd := dsns.Wrap(d, SafemodePrefix)
	var safemodestore, auditstore ds.Batching
	safemodestore = dsns.Wrap(dd, BlocklistPrefix)
	auditstore = dsns.Wrap(dd, AuditPrefix)
	return DatastoreBlocklist{d, auditstore, safemodestore}
}

func (b DatastoreBlocklist) cidToKey(id cid.Cid) (ds.Key, error) {
	// converting cidv0 to cidv1, as all CID are inserted as cidv1 in the compliance database
	cidv1 := id
	if id.Version() == 0 {
		hash, err := mh.FromB58String(id.String())
		if err != nil {
			return ds.NewKey(""), err
		}
		cidv1 = cid.NewCidV1(cid.DagProtobuf, hash)
	}

	return dshelp.CidToDsKey(cidv1), nil
}

// Contains returns true if the blocklist contains the content referenced by
// `id`.
func (b DatastoreBlocklist) Contains(ctx context.Context, id cid.Cid) (bool, error) {
	if !id.Defined() {
		log.Error("undefined cid in blockstore")
		return false, ErrNotFound
	}
	k, err := b.cidToKey(id)
	if err != nil {
		return false, err
	}
	return b.safemodestore.Has(k)
}

func (b DatastoreBlocklist) Block(id cid.Cid, data BlockData) (bool, error) {
	k, err := b.cidToKey(id)
	if err != nil {
		return false, err
	}

	if exists, err := b.Contains(context.TODO(), id); err != nil {
		return false, err
	} else if exists {
		return false, nil
	}

	bi := BlocklistItem{
		Hash:    id.String(),
		Content: data.Content,
		User:    data.User,
		Reason:  data.Reason,
	}
	rawBi, err := bi.MarshalBinary()
	if err != nil {
		return false, err
	}

	if err := b.safemodestore.Put(k, rawBi); err != nil {
		return false, err
	}
	return true, nil
}

func (b DatastoreBlocklist) Unblock(id cid.Cid) error {
	k, err := b.cidToKey(id)
	if err != nil {
		return err
	}
	return b.safemodestore.Delete(k)
}

func (b DatastoreBlocklist) Search(id cid.Cid) (*BlocklistItem, error) {
	k, err := b.cidToKey(id)
	if err != nil {
		return nil, err
	}

	v, err := b.safemodestore.Get(k)
	if err != nil {
		return nil, err
	}

	bi := &BlocklistItem{}
	err = bi.UnmarshalBinary(v)
	if err != nil {
		return nil, err
	}
	return bi, nil
}

func (b DatastoreBlocklist) Purge(id cid.Cid) error {
	k, err := b.cidToKey(id)
	if err != nil {
		return err
	}
	return b.datastore.Delete(k)
}

func (b DatastoreBlocklist) GetLogs(limit int) ([]*Action, error) {
	rr, err := b.auditstore.Query(dsq.Query{
		Orders: []dsq.Order{dsq.OrderByKeyDescending{}},
		Limit:  limit,
	})
	if err != nil {
		return nil, err
	}

	// Unsplit ids
	acts := make([]*Action, 0, limit)
	for res, ok := rr.NextSync(); ok; res, ok = rr.NextSync() {
		l := &Action{}
		err := l.UnmarshalBinary(res.Value)
		if err != nil {
			return nil, err
		}
		acts = append(acts, l)
	}

	return acts, nil
}

func (b DatastoreBlocklist) AddLog(act *Action) error {
	if act.Typ != "block" && act.Typ != "unblock" {
		return fmt.Errorf("unexpected action type: '%v'", act.Typ)
	}
	log.Info(act.String())

	k := ds.NewKey(act.CreatedAt.Format(time.RFC3339))
	rawLi, err := act.MarshalBinary()
	if err != nil {
		return err
	}
	b.auditstore.Put(k, rawLi)

	return nil
}
