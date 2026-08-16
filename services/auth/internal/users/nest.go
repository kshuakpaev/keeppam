package users

import (
	"fmt"

	"github.com/google/uuid"
)

const maxGroupDepth = 8

// nestingOK reports whether child may hang under newParent.
// parentOf maps group → parent (nil/missing = root). descDepth is max
// descendant distance below child (0 = leaf).
func nestingOK(child uuid.UUID, newParent *uuid.UUID, parentOf map[uuid.UUID]*uuid.UUID, descDepth int) error {
	if newParent == nil {
		return nil
	}
	if *newParent == uuid.Nil {
		return nil
	}
	if *newParent == child {
		return fmt.Errorf("group cannot be its own parent")
	}
	nodes := 1 + descDepth
	seen := map[uuid.UUID]struct{}{child: {}}
	cur := *newParent
	for {
		if _, ok := seen[cur]; ok {
			return fmt.Errorf("group cycle")
		}
		seen[cur] = struct{}{}
		nodes++
		if nodes > maxGroupDepth {
			return fmt.Errorf("group nesting deeper than %d", maxGroupDepth)
		}
		p, ok := parentOf[cur]
		if !ok || p == nil || *p == uuid.Nil {
			break
		}
		cur = *p
	}
	return nil
}

func expandGroupAncestors(direct []uuid.UUID, parentOf map[uuid.UUID]*uuid.UUID) map[uuid.UUID]struct{} {
	out := map[uuid.UUID]struct{}{}
	for _, id := range direct {
		cur := id
		for hops := 0; hops < maxGroupDepth; hops++ {
			if _, ok := out[cur]; ok {
				break
			}
			out[cur] = struct{}{}
			p, ok := parentOf[cur]
			if !ok || p == nil || *p == uuid.Nil {
				break
			}
			cur = *p
		}
	}
	return out
}
