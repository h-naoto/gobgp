package server

import (
	"github.com/bouk/monkey"
	"net"
	"os"
	"reflect"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	TCP_MD5SIG = 14
)

type tcpmd5sig struct {
	ss_family uint16
	ss        [126]byte
	pad1      uint16
	keylen    uint16
	pad2      uint32
	key       [80]byte
}

func buildTcpMD5Sig(address string, key string) (tcpmd5sig, error) {
	t := tcpmd5sig{}
	addr := net.ParseIP(address)
	if addr.To4() != nil {
		t.ss_family = syscall.AF_INET
		copy(t.ss[2:], addr.To4())
	} else {
		t.ss_family = syscall.AF_INET6
		copy(t.ss[6:], addr.To16())
	}

	t.keylen = uint16(len(key))
	copy(t.key[0:], []byte(key))

	return t, nil
}

func connToFd(v reflect.Value) int {
	fd := v.FieldByName("fd")
	p := reflect.Indirect(fd)
	sysfd := p.FieldByName("sysfd")
	return int(sysfd.Int())
}

func listenerToFd(l *net.TCPListener) int {
	return connToFd(reflect.ValueOf(*l))
}

func tcpConnToFd(tcp *net.TCPConn) int {
	n := reflect.ValueOf(*tcp)
	return connToFd(n.FieldByName("conn"))
}

func SetTcpMD5SigSockopts(l *net.TCPListener, address string, key string) error {
	t, _ := buildTcpMD5Sig(address, key)
	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(listenerToFd(l)),
		uintptr(syscall.IPPROTO_TCP), uintptr(TCP_MD5SIG),
		uintptr(unsafe.Pointer(&t)), unsafe.Sizeof(t), 0)
	return e
}

func SetTcpTTLSockopts(conn *net.TCPConn, ttl int) error {
	level := syscall.IPPROTO_IP
	name := syscall.IP_TTL
	if strings.Contains(conn.RemoteAddr().String(), "[") {
		level = syscall.IPPROTO_IPV6
		name = syscall.IPV6_UNICAST_HOPS
	}
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(tcpConnToFd(conn), level, name, ttl))
}

func MD5DialTimeout(proto string, host string, time time.Duration, key string) (net.Conn, error) {
	//	t, _ := buildTcpMD5Sig(host, key)
	//	mySyscall := func (trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	//		a4 = uintptr(unsafe.Pointer(&t))
	//		return 0, 0, syscall.ENOSYS
	//	}
	//	monkey.Patch(syscall.Syscall6, mySyscall)
	//	conn, err := net.DialTimeout(proto, host, time)
	//	monkey.Unpatch(syscall.Syscall6)
	//	if err != nil{
	//		return nil, err
	//	}
	//	return conn, nil
	t, _ := buildTcpMD5Sig(host, key)
	myConnect := func(fd int, sa syscall.Sockaddr) error {
		_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd),
			uintptr(syscall.IPPROTO_TCP), uintptr(TCP_MD5SIG),
			uintptr(unsafe.Pointer(&t)), unsafe.Sizeof(t), 0)
		return e
	}
		monkey.Patch(syscall.Connect, myConnect)
		conn, err := net.DialTimeout(proto, host, time)
		monkey.Unpatch(syscall.Syscall6)
		if err != nil{
			return nil, err
		}
		return conn, nil
}
