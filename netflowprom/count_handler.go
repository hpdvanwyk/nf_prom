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
	"encoding/json"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"
)

type CountHandler struct {
	saveFile  string
	doLookups bool

	wg          sync.WaitGroup
	trafficChan chan *IpTraffic
	counts      map[string]*IpTraffic
	lastReset   time.Time
	outGauge    *prometheus.GaugeVec
	inGauge     *prometheus.GaugeVec
}

func NewCountHandler(c chan *IpTraffic, saveFile string, doLookups bool) *CountHandler {
	h := &CountHandler{
		counts:      make(map[string]*IpTraffic),
		trafficChan: c,
		saveFile:    saveFile,
		doLookups:   doLookups,
		outGauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "netflow_byte_count_out",
			Help: "Byte in count of a host.",
		},
			[]string{"host", "hostname"},
		),
		inGauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "netflow_byte_count_in",
			Help: "Byte out count of a host.",
		},
			[]string{"host", "hostname"},
		),
	}
	prometheus.MustRegister(h.outGauge, h.inGauge)
	h.wg.Add(1)
	go h.handleCounts()
	return h
}

func (h *CountHandler) handleCounts() {
	h.loadState()
	ticker := time.NewTicker(60 * time.Second)
	for {
		select {
		case t, ok := <-h.trafficChan:
			if !ok {
				fmt.Printf("shutting down\n")
				h.saveState()
				h.wg.Done()
				return
			}
			h.updateState(t)
		case now := <-ticker.C:
			if now.Month() != h.lastReset.Month() {
				//reset counters
				h.counts = make(map[string]*IpTraffic)
				h.lastReset = now
				h.inGauge.Reset()
				h.outGauge.Reset()
			}
			h.saveState()
		}
	}
}

func (h *CountHandler) loadState() {
	mar, err := ioutil.ReadFile(h.saveFile)
	if err != nil {
		h.lastReset = time.Now()
		fmt.Printf("error reading save file: %v\n", err)
		return
	}
	sf := &SaveFile{}
	err = json.Unmarshal(mar, sf)
	if err != nil {
		h.lastReset = time.Now()
		fmt.Printf("error unmarshalling save file: %v\n", err)
		return
	}
	for _, e := range sf.Entries {
		key := getKey(e)
		h.counts[key] = e
		h.setGauges(e)
	}
	h.lastReset = sf.LastReset
}

func (h *CountHandler) updateState(t *IpTraffic) {
	h.setHostname(t)
	key := getKey(t)

	traffic, ok := h.counts[key]
	if !ok {
		h.counts[key] = t
		h.setGauges(t)
	} else {
		traffic.OutBytes += t.OutBytes
		traffic.InBytes += t.InBytes
		h.setGauges(traffic)
	}
}

func getKey(t *IpTraffic) string {
	return t.Addr.String() + "|" + t.Hostname
}

func (h *CountHandler) saveState() {
	fmt.Printf("\n")
	sf := &SaveFile{}
	sf.LastReset = h.lastReset
	for _, v := range h.counts {
		h.setGauges(v)
		sf.Entries = append(sf.Entries, v)
	}
	mar, err := json.MarshalIndent(sf, "", " ")
	if err != nil {
		fmt.Printf("error marshalling json: %v\n", err)
		return
	}
	ioutil.WriteFile(h.saveFile, mar, 0660)
	if err != nil {
		fmt.Printf("Error writing save file: %v\n", err)
	}
}

func (h *CountHandler) setHostname(t *IpTraffic) {
	if h.doLookups {
		hostnames, err := net.LookupAddr(t.Addr.String())
		if err == nil {
			split := strings.Split(hostnames[0], ".")
			t.Hostname = split[0]
		} else {
			t.Hostname = t.Addr.String()
		}
	} else {
		t.Hostname = t.Addr.String()
	}
}

func (h *CountHandler) setGauges(e *IpTraffic) {
	h.outGauge.With(prometheus.Labels{
		"host":     e.Addr.String(),
		"hostname": e.Hostname,
	}).Set(float64(e.OutBytes))
	h.inGauge.With(prometheus.Labels{
		"host":     e.Addr.String(),
		"hostname": e.Hostname,
	}).Set(float64(e.InBytes))
}

func (h *CountHandler) Wait() {
	h.wg.Wait()
}
