package tn3270

// dbcsTable holds IBM DBCS pair → Unicode for JP/KR codepages (subset for forensic).
var (
	cp930DBCS = map[uint16]rune{
		0x4283: 'カ', 0x4284: 'キ', 0x4285: 'ク', 0x4286: 'ケ', 0x4287: 'コ',
		0x4288: 'サ', 0x4289: 'シ', 0x428A: 'ス', 0x428B: 'セ', 0x428C: 'ソ',
		0x4263: 'あ', 0x4264: 'い', 0x4265: 'う', 0x4266: 'え', 0x4267: 'お',
		0x4268: '日', 0x4269: '本', 0x426A: '語',
	}
	cp939DBCS = map[uint16]rune{
		0x4283: 'カ', 0x4284: 'キ', 0x4263: 'あ', 0x4268: '日', 0x4269: '本',
	}
	cp933DBCS = map[uint16]rune{
		0x4281: '가', 0x4282: '나', 0x4283: '다', 0x4284: '라', 0x4285: '마',
		0x4286: '바', 0x4287: '사', 0x4288: '아', 0x4289: '자', 0x428A: '차',
		0x428B: '카', 0x428C: '타', 0x428D: '파', 0x428E: '하', 0x428F: '한',
	}
)

func dbcsTable(cp Codepage) map[uint16]rune {
	switch cp {
	case CP930:
		return cp930DBCS
	case CP939:
		return cp939DBCS
	case CP933:
		return cp933DBCS
	default:
		return nil
	}
}

func decodeDBCSPair(cp Codepage, lead, trail byte) rune {
	key := uint16(lead)<<8 | uint16(trail)
	if tbl := dbcsTable(cp); tbl != nil {
		if r, ok := tbl[key]; ok {
			return r
		}
	}
	return 0xFFFD
}
