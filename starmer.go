package main

/*
starmer -- proxy by pattern

 tcp conn -------> servername match? ---no-------> internet
                           |
                           +------------yes------> tor
*/

import (
	"bytes"
	"cmp"
	bin "encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	cfgName     = "starmer.ini"
	fallbackCfg = `listenaddr = :1337
toraddr    = localhost:9050
patt       = (imgur|sci-?hub|\.onion$)
`
)

var (
	cfgPath                      string
	cfgTime, re, listenAddr, tor = readCfg()
	enc                          = bin.BigEndian
)

func main() {
	if e := torOK(); e != nil {
		return
	}
	ln, e := net.Listen("tcp", listenAddr)
	if e != nil {
		fmt.Println(e)
		return
	}
	fmt.Printf("proxy-by-pattern listening on %v (socks4a, socks5)\n", listenAddr)
	cfgNote := make(chan int)
	conns := make(chan net.Conn)
	cancel := make(chan int)
	go watchCfg(cfgNote)
	go serve(ln, conns, cancel)
	for {
		select {
		case <-cfgNote:
			fmt.Println("reloading cfg...")
			ln.Close()
			cfgTime, re, listenAddr, tor = readCfg()
			ln, e = net.Listen("tcp", listenAddr)
			if e != nil {
				fmt.Println(e)
				return
			}
			go serve(ln, conns, cancel)
		case c := <-conns:
			go handle(c)
		}
	}
}

func watchCfg(note chan int) {
	for {
		time.Sleep(time.Second)
		fi, e := os.Stat(cfgPath)
		if !fi.ModTime().Equal(cfgTime) {
			fmt.Println("cfg changed...")
			note <- 1
		}
		if e != nil {
			panic(e)
		}
	}
}

func serve(ln net.Listener, c chan net.Conn, cancel chan int) {
	for {
		conn, e := ln.Accept()
		if e != nil {
			fmt.Println(e)
			break
		}
		select {
		case c <- conn:
		case <-cancel:
			break
		}
	}
}

func readCfg() (time.Time, *regexp.Regexp, string, string) {
	dir, _ := os.UserConfigDir()
	cfgPath = filepath.Join(dir, cfgName)

	fmt.Printf("reading %s... ", cfgPath)
	var r io.Reader
	f, e := os.Open(cfgPath)
	if e != nil {
		fmt.Println(e)
		fmt.Printf("creating default %s... ", cfgPath)
		e := os.WriteFile(cfgPath, []byte(fallbackCfg), 0755)
		if e != nil {
			fmt.Println(e)
		}
		r = strings.NewReader(fallbackCfg)
	} else {
		r = f
	}
	fmt.Println()

	var ini *INI
	ini, e = LoadINI(r)
	if e != nil {
		panic(e)
	}

	for _, k := range []string{"listenaddr", "toraddr", "patt"} {
		if ini.Val(k) == "" {
			fmt.Printf("missing %s\n", k)
		}
	}

	fi, e := os.Stat(cfgPath)
	if e != nil {
		panic(e)
	}
	return fi.ModTime(), regexp.MustCompile(ini.Val("patt")), ini.Val("listenaddr"), ini.Val("toraddr")
}

func handle(clConn net.Conn) {
	defer clConn.Close()

	// recv client connect
	var dialAddr string
	var ver byte
	if e := read(clConn, &ver); e != nil {
		ioerr(e)
		return
	}
	switch ver {
	case 4:
		var p1 = struct {
			Cmd     byte
			DstPort uint16
			DstIP   [4]byte
		}{}
		if e := read(clConn, &p1); e != nil {
			ioerr(e)
			return
		}
		if p1.Cmd != 1 {
			fmt.Printf("bad cmd %d\n", p1.Cmd)
			return
		}
		_ = readStr0(clConn) // skip id
		addrstr := ip2str(p1.DstIP)
		if addrstr == "0.0.0.1" {
			// recv SOCKS4a domain name
			hostname := readStr0(clConn)
			addrstr = hostname
		}
		dialAddr = fmt.Sprintf("%s:%d", addrstr, p1.DstPort)

		// send request granted
		clConn.Write([]byte{0, 0x5A, 0, 0, 0, 0, 0, 0})
	case 5:
		var nmeths uint16
		read(clConn, &nmeths)
		meths := make([]byte, clamp(nmeths, 1, 255))
		if nmeths > 0 {
			read(clConn, meths) // skip methods
		}

		// send selected auth method
		clConn.Write([]byte{5, 0})

		// recv request details
		s := struct {
			Ver, Cmd, Rsv, ATyp byte
		}{}
		read(clConn, &s)
		fmt.Println(s)
		if s.ATyp != 1 {
			fmt.Println("unsupported address type")
			return
		}
		// FIXME: read domain (atyp 3)
		addr := struct {
			Addr [4]byte
			Port uint16
		}{}
		read(clConn, &addr)
		dialAddr = fmt.Sprintf("%s:%d", ip2str(addr.Addr), addr.Port)

		// send request granted
		if _, e := clConn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
			ioerr(e)
			return
		}
	default:
		b := make([]byte, 0xFFFF)
		n, _ := clConn.Read(b)
		b = b[:n]
		fmt.Printf("bad socks version:%d, rest of data:%s\n", ver, packet2str(b))
		return
	}

	// recv client hello
	hello, tunnel := readHello(clConn)
	var tgtConn net.Conn
	if tunnel {
		// tunnel through proxy
		fmt.Printf("    tunnel  %s\n", dialAddr)
		var e error
		tgtConn, e = dialTor(dialAddr)
		if e != nil {
			fmt.Println(e)
			return
		}
	} else {
		// dial the requested target
		fmt.Printf("    fwd     %s\n", dialAddr)
		var e error
		tgtConn, e = net.Dial("tcp", dialAddr)
		if e != nil {
			fmt.Println(e)
			return
		}
		defer tgtConn.Close()
	}

	// fwd the client hello that we intercepted
	tgtConn.Write(hello)

	// fwd clConn->tgtConn, and tgtConn->clConn
	go func() {
		n, e := clConn.(*net.TCPConn).WriteTo(tgtConn)
		if e != nil && e != io.EOF && e != net.ErrClosed {
			fmt.Printf("tgt->cl %v %v\n", n, e)
		}
	}()
	n, e := tgtConn.(*net.TCPConn).WriteTo(clConn)
	if e != nil && e != io.EOF && e != net.ErrClosed {
		fmt.Printf("tgt->cl %v %v\n", n, e)
	}
}

func clamp[T cmp.Ordered](x, lo, hi T) T { return min(max(lo, x), hi) }
func read(r io.Reader, x any) error      { return bin.Read(r, enc, x) }
func write(w io.Writer, x any) error     { return bin.Write(w, enc, x) }
func ip2str(ip [4]byte) string           { return net.IP(ip[:]).String() }

func ioerr(e error) {
	if e != nil && e != io.EOF && e != net.ErrClosed {
		fmt.Println(e)
	}
}

func readHello(conn net.Conn) ([]byte, bool) {
	buf := make([]byte, 10000)
	n, e := conn.Read(buf)
	if e != nil {
		fmt.Println(e)
		return nil, false
	}

	// TLS:  [0] = 0x16 client hello, match against SNI
	// HTTP: [0..] = GET/POST, match against host field
	if !((len(buf) >= 1 && buf[0] == 0x16) ||
		(len(buf) >= 3 && bytes.Equal(buf[0:3], []byte("GET"))) ||
		(len(buf) >= 4 && bytes.Equal(buf[0:4], []byte("POST")))) {
		return buf[:n], false
	}
	return buf[:n], re.Match(buf[:n])
}

func packet2str(p []byte) string {
	var b strings.Builder

	const w = 8
	for i := 0; i < len(p); i += w {
		by := p[i : i+min(w, len(p)-i)]
		hx := fmt.Sprintf("% 02X", by)
		b.WriteString(fmt.Sprintf("%-25s%s\n", hx, string(by)))
	}
	return b.String()
}

func readStr0(conn net.Conn) string {
	var s strings.Builder
	var x [1]byte
	for {
		n, e := conn.Read(x[:])
		if n == 0 || x[0] == 0 || e != nil {
			break
		}
		s.WriteByte(x[0])
	}
	return s.String()
}

func dialTor(addr string) (net.Conn, error) {
	ss := strings.Split(addr, ":")
	host := ss[0]
	port, _ := strconv.Atoi(ss[1])

	var atyp byte
	var addrbytes []byte
	if ip := net.ParseIP(host); ip != nil {
		addrbytes = ip[12:] // ipv4
		atyp = 1
	} else if ipaddr, _ := net.ResolveIPAddr("ip", host); ipaddr != nil {
		addrbytes = ipaddr.IP[:]
		atyp = 1
	} else {
		addrbytes = append([]byte{byte(len(host))}, []byte(host)...)
		atyp = 3
	}

	c, e := net.Dial("tcp", tor)
	if e != nil {
		return c, e
	}

	// send client connect
	c.Write([]byte{5, 1, 0})

	// recv server select
	b := make([]byte, 100)
	c.Read(b)

	// send request details
	c.Write([]byte{5, 1, 0, atyp})
	write(c, addrbytes)
	write(c, uint16(port))

	// recv request granted
	_, e = c.Read(b)
	return c, e
}

func torOK() error {
	fmt.Printf("testing tor proxy at %v... ", tor)
	c, e := dialTor("example.org:443")
	if e != nil {
		fmt.Printf("bad: %v", e)
	} else {
		c.Close()
	}
	fmt.Println()
	return e
}
