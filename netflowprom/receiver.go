/*
Copyright (c) 2017 Hendrik van Wyk
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package netflowprom

import (
	"fmt"
	"github.com/fln/nf9packet"
	"net"
	"os"
	"sync"
	"time"
)

type IpTraffic struct {
	Addr     net.IP
	OutBytes uint64
	InBytes  uint64
	Hostname string
}

type SaveFile struct {
	LastReset time.Time
	Entries   []*IpTraffic
}

type templateCache map[string]*nf9packet.TemplateRecord

var rfc1918 []*net.IPNet

func init() {
	_, privateBlock, _ := net.ParseCIDR("10.0.0.0/8")
	rfc1918 = append(rfc1918, privateBlock)
	_, privateBlock, _ = net.ParseCIDR("172.16.0.0/12")
	rfc1918 = append(rfc1918, privateBlock)
	_, privateBlock, _ = net.ParseCIDR("192.168.0.0/16")
	rfc1918 = append(rfc1918, privateBlock)
}

type Receiver struct {
	closing chan struct{}
	wg      sync.WaitGroup
	con     *net.UDPConn
	C       chan *IpTraffic
}

func NewReceiver(listenAddr string) (*Receiver, error) {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}

	con, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	r := &Receiver{
		closing: make(chan struct{}),
		con:     con,
		C:       make(chan *IpTraffic, 10),
	}
	r.wg.Add(1)
	go r.receive()
	return r, nil
}

func (r *Receiver) receive() {
	data := make([]byte, (1<<16)-1)
	cache := make(templateCache)

	for {
		length, remote, err := r.con.ReadFrom(data)
		if err != nil {
			select {
			case <-r.closing:
				close(r.C)
				r.wg.Done()
				return
			default:
			}
			panic(err)
		}

		r.parseNetflow(remote.String(), data[:length], cache)
	}
}

func (r *Receiver) parseNetflow(addr string, data []byte, cache templateCache) {
	p, err := nf9packet.Decode(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	templateList := p.TemplateRecords()
	flowSets := p.DataFlowSets()

	for _, t := range templateList {
		templateKey := fmt.Sprintf("%s|%b|%v", addr, p.SourceId, t.TemplateId)
		cache[templateKey] = t
	}

	for _, set := range flowSets {
		templateKey := fmt.Sprintf("%s|%b|%v", addr, p.SourceId, set.Id)
		template, ok := cache[templateKey]
		if !ok {
			// We do not have template for this Data FlowSet yet
			continue
		}

		records := template.DecodeFlowSet(&set)
		if records == nil {
			// Error in decoding Data FlowSet
			continue
		}
		r.parseNetflowRecord(template, records)
	}
}

func (r *Receiver) parseNetflowRecord(template *nf9packet.TemplateRecord, records []nf9packet.FlowDataRecord) {
	ip4SourceIndex, err := findFieldIndex(template, "IPV4_SRC_ADDR")
	if err != nil {
		// can't do anything with these records
		return
	}
	ip4DstIndex, err := findFieldIndex(template, "IPV4_DST_ADDR")
	if err != nil {
		// can't do anything with these records
		return
	}
	bytesIndex, err := findFieldIndex(template, "IN_BYTES")
	if err != nil {
		// can't do anything with these records
		return
	}

	for _, rec := range records {
		if len(rec.Values) <= ip4SourceIndex {
			continue
		}
		srcIP := net.IP(rec.Values[ip4SourceIndex])
		if len(rec.Values) <= ip4DstIndex {
			continue
		}
		dstIP := net.IP(rec.Values[ip4DstIndex])
		if len(rec.Values) <= bytesIndex {
			continue
		}
		bytesCount := template.Fields[bytesIndex].DataToUint64(rec.Values[bytesIndex])
		if !(srcIP.IsGlobalUnicast() && dstIP.IsGlobalUnicast()) {
			// Skip broadcasts and other funny addresses.
			continue
		}

		srcLocal := isRFC1918(srcIP)
		dstLocal := isRFC1918(dstIP)
		switch {
		case srcLocal == true && dstLocal == true:
			// Local packet. Just ignore it.
		case srcLocal == true:
			tr := &IpTraffic{
				Addr:     srcIP,
				OutBytes: bytesCount,
			}
			r.C <- tr
		case dstLocal == true:
			tr := &IpTraffic{
				Addr:    dstIP,
				InBytes: bytesCount,
			}
			r.C <- tr
		}
	}
}

func findFieldIndex(template *nf9packet.TemplateRecord, fieldType string) (int, error) {
	for i, f := range template.Fields {
		if f.Name() == fieldType {
			return i, nil
		}
	}
	return 0, fmt.Errorf("could not find field type %v", fieldType)
}

func isRFC1918(ip net.IP) bool {
	for _, block := range rfc1918 {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *Receiver) Close() error {
	close(r.closing)
	r.con.Close()
	r.wg.Wait()
	return nil
}
