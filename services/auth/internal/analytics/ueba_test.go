package analytics

import "testing"

func TestDetectUEBA(t *testing.T) {
	hits := []UEBAHit{
		{Actor: "ivan", Baseline: 3, RecentDistinct: 4, NewAssets: 1, NewNames: []string{"db-prod"}},
		{Actor: "petr", Baseline: 3, RecentDistinct: 6, NewAssets: 3, Spread: true},
	}
	anoms := detect(Stats{}, nil, 24, SIEMCorr{}, nil, nil, hits)
	if len(anoms) != 2 {
		t.Fatalf("len=%d", len(anoms))
	}
	if anoms[0].Code != "ueba_spread" || anoms[0].Severity != "high" {
		t.Fatalf("spread first after sort: %+v", anoms[0])
	}
	if anoms[1].Code != "ueba_new_asset" || anoms[1].Actor != "ivan" {
		t.Fatalf("new asset: %+v", anoms[1])
	}
}
