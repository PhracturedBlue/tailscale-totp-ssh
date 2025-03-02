
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"time"
)

func isIPInSubnet(ipAddress string, subnet string) bool {
	ip := net.ParseIP(ipAddress)
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return false // Invalid subnet format
	}
	return ipnet.Contains(ip)
}

func checkIPAddress(ip_address string) bool {
	if len(configAllowedSubnets) > 0 {
		ok := false
		for _, subnet := range configAllowedSubnets {
			if isIPInSubnet(ip_address, subnet) {
				ok = true
				break
			}
		}
		return ok
	}
	return true
}

func lookupIP(host string) ([]string, error) {
	if *configDNSServer != "" {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{ Timeout: time.Millisecond * time.Duration(10000), }
				return d.DialContext(ctx, network, *configDNSServer + ":53")
			},
		}
		ips, err := r.LookupHost(context.Background(), host)
		if err != nil {
			return nil, err
		}
		return ips, nil
	} else {
		ips, err := net.LookupHost(host)
		if err != nil {
			return nil, err
		}
		return ips, nil
	}
}

func validateHostPort(host string, port uint32) (string, error) {
	r := regexp.MustCompile("^(?:(\\d+\\.\\d+\\.\\d+\\.\\d+)|([a-z0-9-]+)(?:\\.([a-z0-9-][[a-z0-9-.]+))?)$")
	match := r.FindStringSubmatch(host)
	if match == nil {
		return "", errors.New("Invalid host: " + host)
	}
	ip_address, hostname, domain := match[1], match[2], match[3]
	if ip_address == "" {
		if len(configAllowedDomains) > 0 {
			ok := false
			for _, dom := range configAllowedDomains {
				if domain == dom {
					ok = true
					break
				}
			}
			if ! ok {
				return "", fmt.Errorf("Invalid domain '%s'", domain)
			}
		}
		log.Printf("Looking up: %s", host)
		ips, err := lookupIP(host)
		if err != nil {
			return "", fmt.Errorf("Error looking up IP addresses for %s: %v\n", host, err)
		}
		for _, ip := range ips {
			if checkIPAddress(ip) {
				ip_address = ip
				break
			}
		}
		if ip_address == "" {
			return "", fmt.Errorf("No valid IP address found for %s.%s", hostname, domain)
		}
	} else if ! checkIPAddress(ip_address) {
		return "", fmt.Errorf("Invalid IP '%s'", ip_address)
	}
	if len(configAllowedPortRanges) > 0 {
		ok := false
		for _, portRange := range configAllowedPortRanges {
			if port >= portRange[0] && port <= portRange[1] {
				ok = true
				break
			}
		}
		if ! ok {
			return "", fmt.Errorf("Invalid port '%d'", port)
		}
	}
	return ip_address, nil
}

func parseUserHostPort(line string) (string, string, string, error) {
	r := regexp.MustCompile("^([a-z0-9]+)@(\\d+\\.\\d+\\.\\d+\\.\\d+|[a-z0-9-]+\\.[a-z0-9-][[a-z0-9-.]+)(?::(\\d+))?$")
	match := r.FindStringSubmatch(line)
	if match == nil {
		return "", "", "", errors.New("Invalid format: " +  line)
	}
	user, host, port := match[1], match[2], match[3]
	if port == "" {
		port = "22"
	}
	port_num, _ := strconv.ParseUint(port, 10, 32)
	host, err := validateHostPort(host, uint32(port_num))
	if err != nil {
		return "", "", "", err
	}
	return user, host, ":" + port, nil
}
