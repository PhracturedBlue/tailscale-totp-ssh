// Flags

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"path/filepath"
)

var (
	configTOTP = flag.String("totp", "", "totp secret")
	configTSName      = flag.String("tsname", "", "tailscale name")
	configLoginUser   = flag.String("user", "", "login user")
	configStateDir    = flag.String("statedir", "", "Tailscale state dir")
	configHostKeyFile = flag.String("hostkey", "./id_rsa", "Host key file")
	configDNSServer   = flag.String("dnsserver", "", "Specify DNS Server")
	configVerbose     = flag.Bool("verbose", false, "if set, verbosely log tsnet information")
	configPort        = flag.Int("port", 22, "listen port")
	configNoPassword  = flag.Bool("no-password", false, "if set, don't require a password")
	configNoTailscale = flag.Bool("no-tailscale", false, "if set, don't start tailscale")
	configAllowedDomains      stringArrayFlags
	configAllowedSubnets      stringArrayFlags
	configAllowedPortRanges   intRangeArrayFlags
)

type stringArrayFlags []string

func (i *stringArrayFlags) String() string {
	return strings.Join(*i, ", ")
}

func (i *stringArrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

type intRangeArrayFlags [][2]uint32

func (i *intRangeArrayFlags) String() string {
	pairs := []string{}
	for _, item := range *i {
		if item[0] == item[1] {
			pairs = append(pairs, fmt.Sprintf("%d", item[0]))
		} else {
			pairs = append(pairs, fmt.Sprintf("%d-%d", item[0], item[1]))
		}
	}
	return strings.Join(pairs, ", ")
}

func (i *intRangeArrayFlags) Set(value string) error {
	rng := strings.Split(value, "-")
	if len(rng) == 1 {
		val, err := strconv.ParseUint(rng[0], 10, 32)
		if err != nil {
			return err
		}
		*i = append(*i, [2]uint32{uint32(val), uint32(val)})
	} else if len(rng) == 2 {
		val1, err := strconv.ParseUint(rng[0], 10, 32)
		if err != nil {
			return err
		}
		val2, err := strconv.ParseUint(rng[1], 10, 32)
		if err != nil {
			return err
		}
		*i = append(*i, [2]uint32{uint32(val1), uint32(val2)})
	} else {
		return errors.New("Invalid format for " + value)
	}
	return nil
}

// Parse flags and validate them as needed
func initializeFlags() {
	flag.Var(&configAllowedDomains, "jump_domains", "Restrict allowed jump domains")
	flag.Var(&configAllowedSubnets, "jump_subnets", "Restrict allowed jump subnets")
	flag.Var(&configAllowedPortRanges, "jump_ports", "Restrict allowed jump ports (specify # or from-to)")
	flag.Parse()
	if (*configTSName == "" && ! *configNoTailscale) {
		log.Fatalf("-tsname is a required flag")
	}
	if (*configStateDir == "") {
		defaultDirectory, err := os.UserConfigDir()
		if err != nil {
			log.Fatalf("can't find default user config directory: %v", err)
		}
		*configStateDir = filepath.Join(defaultDirectory, "tailscale-totp-ssh")
	}
	log.Printf("Using config dir: %s", *configStateDir)
	if _, err := os.Stat(*configHostKeyFile); err != nil {
		log.Fatalf("Host key file %s dos not exist.  Generate with\nssh-keygen -f %s", *configHostKeyFile, *configHostKeyFile)
	}
	if len(configAllowedDomains) > 0 {
		log.Printf("Restrict jump domains to %s", configAllowedDomains.String());
	}
	if len(configAllowedSubnets) > 0 {
		for _, subnet := range configAllowedSubnets {
			_, _, err := net.ParseCIDR(subnet)
			if err != nil {
				log.Fatalf("Invalid subnet: %s", subnet)
			}
		}
		log.Printf("Restrict jump subnets to %s", configAllowedSubnets.String());
	}
	if len(configAllowedPortRanges) > 0 {
		log.Printf("Restrict jump ports to: %s", configAllowedPortRanges.String())
	}
}

