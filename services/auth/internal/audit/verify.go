package audit

import (
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/store"
)

type Break struct {
	Index  int       `json:"index"`
	ID     uuid.UUID `json:"id"`
	Reason string    `json:"reason"`
}

type VerifyResult struct {
	OK             bool    `json:"ok"`
	Events         int     `json:"events"`
	DigestOK       int     `json:"digest_ok"`
	DigestMismatch int     `json:"digest_mismatch"`
	Breaks         []Break `json:"breaks"`
	HeadHash       string  `json:"head_hash,omitempty"`
	TailHash       string  `json:"tail_hash,omitempty"`
	Unsealed       int     `json:"unsealed"`
	Batches        int     `json:"batches"`
	BatchMACOK     int     `json:"batch_mac_ok"`
	BatchMACFail   int     `json:"batch_mac_fail"`
	BatchLinkFail  int     `json:"batch_link_fail"`
}

func CheckEvents(events []store.AuditEvent) VerifyResult {
	var st chainState
	for i := range events {
		st.add(i, events[i])
	}
	st.finish()
	return st.res
}

type chainState struct {
	res  VerifyResult
	prev string
}

func (st *chainState) add(i int, e store.AuditEvent) {
	st.res.Events++
	if i == 0 {
		st.res.HeadHash = e.Hash
		if e.PrevHash != "" {
			st.breakAt(i, e.ID, "first_prev")
		}
	} else if e.PrevHash != st.prev {
		st.breakAt(i, e.ID, "bad_prev")
	}
	if HashEvent(e) == e.Hash {
		st.res.DigestOK++
	} else {
		st.res.DigestMismatch++
	}
	st.prev = e.Hash
	st.res.TailHash = e.Hash
}

func (st *chainState) breakAt(i int, id uuid.UUID, reason string) {
	if len(st.res.Breaks) < 20 {
		st.res.Breaks = append(st.res.Breaks, Break{Index: i, ID: id, Reason: reason})
	}
}

func (st *chainState) finish() {
	if st.res.Breaks == nil {
		st.res.Breaks = []Break{}
	}
	st.res.OK = len(st.res.Breaks) == 0 && st.res.BatchMACFail == 0 && st.res.BatchLinkFail == 0
}
