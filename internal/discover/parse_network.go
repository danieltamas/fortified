package discover

import (
	"strconv"
	"strings"
)

// dbPorts are well-known database/cache ports discover checks for
// exposure — a port outside this list isn't flagged even if bound to
// 0.0.0.0, since SPEC.md §5's mandatory flag is specifically about
// DB/cache ports.
var dbPorts = map[int]bool{
	5432:  true, // postgres
	3306:  true, // mysql/mariadb
	6379:  true, // redis
	27017: true, // mongodb
	9200:  true, // elasticsearch
	11211: true, // memcached
}

// allInterfaceAddresses are "bound everywhere" spellings ss can print.
var allInterfaceAddresses = map[string]bool{
	"0.0.0.0": true,
	"*":       true,
	"[::]":    true,
	"::":      true,
}

// parsePortBindings parses `ss -tlnp` output.
func parsePortBindings(cap *Capture) []PortBinding {
	r, ok := cap.get(cmdSSTlnp)
	if !ok || commandMissing(r) {
		return nil
	}

	var bindings []PortBinding
	lines := strings.Split(r.Stdout, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] != "LISTEN" {
			continue
		}
		addr, port, ok := splitAddrPort(fields[3])
		if !ok {
			continue
		}
		bindings = append(bindings, PortBinding{
			Address: addr,
			Port:    port,
			Process: strings.Join(fields[5:], " "),
		})
	}
	return bindings
}

// splitAddrPort splits ss's "address:port" column on the last colon —
// safe for IPv4 ("127.0.0.1:9008"), bracketed IPv6 ("[::]:443"), and
// scoped addresses ("127.0.0.53%lo:53").
func splitAddrPort(field string) (addr string, port int, ok bool) {
	i := strings.LastIndex(field, ":")
	if i < 0 {
		return "", 0, false
	}
	portNum, err := strconv.Atoi(field[i+1:])
	if err != nil {
		return "", 0, false
	}
	return field[:i], portNum, true
}

// findExposure builds ExposureFinding entries for DB/cache ports bound
// to all interfaces. egressIP is the control host's own public IP
// (empty if it couldn't be determined); firewallText is the raw
// concatenated firewall-rule output discover captured. Per SPEC.md
// §5, a finding is never silently downgraded to "not exposed" — it is
// either "exposed" or, when the control host's own IP already appears
// in the target's allowlist (so a positive reachability result from
// here wouldn't prove general exposure), "unverifiable".
func findExposure(bindings []PortBinding, containers []Container, egressIP, firewallText string) []ExposureFinding {
	var findings []ExposureFinding
	for _, b := range bindings {
		if !dbPorts[b.Port] || !allInterfaceAddresses[b.Address] {
			continue
		}

		severity, reason := SeverityExposed, "bound to all interfaces on a database/cache port"
		if egressIP != "" && strings.Contains(firewallText, egressIP) {
			severity = SeverityUnverifiable
			reason = "control host's own egress IP (" + egressIP + ") appears in the target's firewall rules; " +
				"testing from this vantage point cannot prove general exposure (SKILL.md Step 0)"
		}

		findings = append(findings, ExposureFinding{
			Container: containerForPort(containers, b.Port),
			Address:   b.Address,
			Port:      b.Port,
			Process:   b.Process,
			Severity:  severity,
			Reason:    reason,
		})
	}
	return findings
}

func containerForPort(containers []Container, port int) string {
	needle := ":" + strconv.Itoa(port) + "->"
	for _, c := range containers {
		if strings.Contains(c.Ports, needle) {
			return c.Name
		}
	}
	return ""
}
