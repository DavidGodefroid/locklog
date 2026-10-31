package mask



// maxNames bounds the console-memory name book.
const maxNames = 10000

// nameBook keeps, in the console's memory only, the clear names behind the
// ⟦key:ID⟧ shown this epoch (so that an agent rule naming one can be
// translated) and the names shown in clear per source (an agent rule may
// name only those). Nothing in it is saved.
type nameBook struct {
	masked map[string]string          // ID -> clear name
	clear  map[string]map[string]bool // source -> names shown in clear
	nClear int
}

func newNameBook() nameBook {
	return nameBook{masked: map[string]string{}, clear: map[string]map[string]bool{}}
}

func (m *Masker) noteMasked(id, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.names.masked) >= maxNames {
		if _, ok := m.names.masked[id]; !ok {
			return
		}
	}
	m.names.masked[id] = name
}

func (m *Masker) noteClear(source, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := m.names.clear[source]
	if set == nil {
		set = map[string]bool{}
		m.names.clear[source] = set
	}
	if !set[name] && m.names.nClear < maxNames {
		set[name] = true
		m.names.nClear++
	}
}

func (m *Masker) maskedName(id string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.names.masked[id]
	return n, ok
}

func (m *Masker) shownClear(source, name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.names.clear[source][name]
}

