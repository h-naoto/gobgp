// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"

	"github.com/osrg/gobgp/packet"
	"net"
	"os"
	"strconv"
)

func connLoop(conn *net.TCPConn) {
	addr := conn.RemoteAddr()
	scanner := bufio.NewScanner(bufio.NewReader(conn))
	scanner.Split(bgp.SplitBMP)

	for scanner.Scan() {
		msg, err := bgp.ParseBMPMessage(scanner.Bytes())
		if err != nil {
			continue
		}
		j, _ := json.Marshal(msg)
		fmt.Print(string(j), "\n")
	}
}

func main() {
	service := ":" + strconv.Itoa(bgp.BMP_DEFAULT_PORT)
	addr, _ := net.ResolveTCPAddr("tcp", service)

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
	os.Exit(1)
	}

	for {
		conn, err := l.AcceptTCP()
		if err != nil {
			continue
		}

		go connLoop(conn)
	}
}
