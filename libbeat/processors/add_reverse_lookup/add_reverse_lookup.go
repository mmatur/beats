package add_reverse_lookup

import (
	"fmt"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/common/cfgwarn"
	"github.com/elastic/beats/libbeat/processors"
	"net"
)

type addReverseLookup struct {
	IpField                  string
	HostnameField            string
	reverseLookup            *ReverseLookupCache
	HostnameErrorField       error
	HostnameEtldPlusOneField string
	ExcludePrivateDomain     bool
}

func init() {
	processors.RegisterPlugin("add_reverse_lookup", newAddReverseLookup)
}

func newAddReverseLookup(c *common.Config) (processors.Processor, error) {
	cfgwarn.Beta("The add_reverse_lookup processor is beta")

	config := defaultConfig()

	err := c.Unpack(&config)
	if err != nil {
		return nil, fmt.Errorf("fail to unpack the add_reverse_lookup configuration: %s", err)
	}

	var reverseLookup addReverseLookup

	reverseLookup.IpField = config.IpField
	reverseLookup.HostnameField = config.HostnameField
	var successTTL, failureTTL = defSuccessTTL, defFailureTTL
	if config.SuccessTTL != 0 {
		successTTL = config.SuccessTTL
	}
	if config.FailureTTL != 0 {
		successTTL = config.FailureTTL
	}
	reverseLookup.reverseLookup = NewReverseLookupCache(successTTL, failureTTL)

	return reverseLookup, nil
}

func (r addReverseLookup) Run(event *beat.Event) (*beat.Event, error) {
	// Reverse DNS lookup on the remote IP.
	if r.reverseLookup != nil {
		ip, _, err := net.ParseCIDR(r.HostnameField)
		if err != nil {
			fmt.Println("Error", event.Fields[r.HostnameField], err)
			return nil, fmt.Errorf("fail to parse %s ", r.HostnameField)
		}
		hostname, err := r.reverseLookup.Lookup(ip, r.ExcludePrivateDomain)
		if err != nil {
			r.HostnameErrorField = err
		} else {
			event.PutValue(r.HostnameField, hostname)
			hostnameEtldPlusOne, _ := etldPlusOne(hostname)
			event.PutValue(r.HostnameEtldPlusOneField, hostnameEtldPlusOne)
		}
	}

	return event, nil
}

func (r addReverseLookup) String() string {
	return "add_reverse_lookup=[IpField=" + r.IpField + "]"
}
