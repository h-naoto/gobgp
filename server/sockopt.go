package server

import (
	"net"
	"os"
	"reflect"
	"strings"
	"syscall"
	"unsafe"
	log "github.com/Sirupsen/logrus"
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
	cdf := connToFd(n.FieldByName("conn"))
	log.Error("SOCKOPT: %s", cdf)
	return cdf
}

func setFd(family uint16) (int error){
	syscall.ForkLock.RLock()
	s, err := syscall.Socket(family, syscall.SOCK_STREAM , 0)
	if err == nil {
		syscall.CloseOnExec(s)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return -1, err
	}
	if err = syscall.SetNonblock(s, true); err != nil {
		syscall.Close(s)
		return -1, err
	}
	return s, nil
}

func SetTcpMD5SigSockopts(l *net.TCPListener, address string, key string) error {
	t, _ := buildTcpMD5Sig(address, key)
	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(listenerToFd(l)),
		uintptr(syscall.IPPROTO_TCP), uintptr(TCP_MD5SIG),
		uintptr(unsafe.Pointer(&t)), unsafe.Sizeof(t), 0)
	return e
}

func SetTcpMD5SigSockoptsConn(address string, key string) error {
	t, _ := buildTcpMD5Sig(address, key)
	fd, e:= setFd(t.ss_family)
	if e != nil {
		return e
	}
	_, _, e = syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd),
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
