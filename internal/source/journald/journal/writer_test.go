package journal

import (
	"encoding/binary"

	"github.com/klauspost/compress/zstd"
)

// testFile builds a minimal journal file in memory: header, DATA objects,
// ENTRY objects and one ENTRY_ARRAY (no hash tables: the reader does not
// use them). It exists to make small fuzz seeds and corrupt variants.
type testFile struct {
	compact bool
	zstd    bool // compress every DATA payload
	buf     []byte
	entries []uint64
	dataOff map[string]uint64
}

type testEntry struct {
	realtime uint64
	fields   []string // "NAME=value"
}

func (t *testFile) obj(typ, flags uint8, body []byte) uint64 {
	off := uint64(len(t.buf))
	size := objectHeaderSize + len(body)
	h := make([]byte, objectHeaderSize)
	h[0], h[1] = typ, flags
	binary.LittleEndian.PutUint64(h[8:], uint64(size))
	t.buf = append(t.buf, h...)
	t.buf = append(t.buf, body...)
	for len(t.buf)%8 != 0 {
		t.buf = append(t.buf, 0)
	}
	return off
}

func (t *testFile) data(payload string) uint64 {
	if off, ok := t.dataOff[payload]; ok {
		return off
	}
	head := 48 // hash, next_hash, next_field, entry, entry_array, n_entries
	if t.compact {
		head += 8
	}
	body := make([]byte, head)
	p := []byte(payload)
	var flags uint8
	if t.zstd {
		enc, _ := zstd.NewWriter(nil)
		p = enc.EncodeAll(p, nil)
		enc.Close()
		flags = objCompressedZSTD
	}
	off := t.obj(typeData, flags, append(body, p...))
	t.dataOff[payload] = off
	return off
}

func buildJournal(compact, z bool, es []testEntry) []byte {
	t := &testFile{compact: compact, zstd: z, dataOff: map[string]uint64{}}
	t.buf = make([]byte, 272)
	for i, e := range es {
		var items []byte
		for _, f := range e.fields {
			d := t.data(f)
			if compact {
				items = binary.LittleEndian.AppendUint32(items, uint32(d))
			} else {
				items = binary.LittleEndian.AppendUint64(items, d)
				items = binary.LittleEndian.AppendUint64(items, 0)
			}
		}
		body := make([]byte, 48)
		binary.LittleEndian.PutUint64(body[0:], uint64(i+1))
		binary.LittleEndian.PutUint64(body[8:], e.realtime)
		binary.LittleEndian.PutUint64(body[16:], uint64(1000+i))
		t.entries = append(t.entries, t.obj(typeEntry, 0, append(body, items...)))
	}
	arr := make([]byte, 8)
	for _, off := range t.entries {
		if compact {
			arr = binary.LittleEndian.AppendUint32(arr, uint32(off))
		} else {
			arr = binary.LittleEndian.AppendUint64(arr, off)
		}
	}
	arrOff := t.obj(typeEntryArray, 0, arr)
	h := t.buf[:272]
	copy(h, signature)
	incompat := uint32(0)
	if compact {
		incompat |= incompatCompact
	}
	if z {
		incompat |= incompatZSTD
	}
	le := binary.LittleEndian
	le.PutUint32(h[12:], incompat)
	le.PutUint64(h[88:], 272)
	le.PutUint64(h[96:], uint64(len(t.buf)-272))
	le.PutUint64(h[136:], arrOff)
	le.PutUint64(h[152:], uint64(len(es)))
	le.PutUint64(h[176:], arrOff)
	if len(es) > 0 {
		le.PutUint64(h[184:], es[0].realtime)
		le.PutUint64(h[192:], es[len(es)-1].realtime)
	}
	return t.buf
}
