package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
)

type INI struct {
	Name     string
	Keys     []string
	Sections []string
	vals     map[string]string
	secs     map[string]*INI
}

func newSection(sectionName string) *INI {
	return &INI{
		Name: sectionName,
		vals: make(map[string]string, 8),
		secs: make(map[string]*INI, 8),
	}
}

func (ini *INI) addSection(name string) *INI {
	if s, ok := ini.secs[name]; ok {
		return s
	}
	ini.Sections = append(ini.Sections, name)
	s := newSection(name)
	ini.secs[name] = s
	return s
}

func (ini *INI) Val(key string) string {
	return ini.vals[key]
}

func (ini *INI) Section(name string) *INI {
	return ini.secs[name]
}

func LoadINI(r io.Reader) (*INI, error) {
	global := newSection("")
	sec := global

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		b := sc.Bytes()
		b = bytes.TrimLeft(b, " \t")
		if len(b) == 0 {
			continue
		}

		switch b[0] {
		case ';':
			continue
		case ']', '=':
			return nil, fmt.Errorf("unexpected '%c'", b[0])
		case '[':
			i := bytes.Index(b, []byte{']'})
			if i == -1 {
				return nil, fmt.Errorf("expected ']'")
			}
			if i != len(b)-1 {
				return nil, fmt.Errorf("trailing characters after ']'")
			}

			b = bytes.Trim(b[1:len(b)-1], " \t")
			if len(b) == 0 {
				return nil, fmt.Errorf("empty section name")
			}
			sec = global
			name := bytes.Split(b, []byte{'.'})
			for i := range name {
				if len(name[i]) == 0 {
					return nil, fmt.Errorf("empty subsection name")
				}
				sec = sec.addSection(string(name[i]))
			}
		default:
			s := bytes.SplitN(b, []byte{'='}, 2)
			if len(s) != 2 || len(s[1]) == 0 {
				return nil, fmt.Errorf("expected key = value")
			}

			k := string(bytes.TrimRight(s[0], " \t"))
			sec.Keys = append(sec.Keys, k)

			v := string(bytes.TrimLeft(s[1], " \t"))
			sec.vals[k] = v
		}
	}
	return global, nil
}
