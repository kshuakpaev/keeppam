package firewall

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	maxGatewayCIDRs = 16
	maxCIDRLen      = 64
)

// ValidateGatewayCIDRs normalizes PAM gateway source CIDRs for firewall export.
func ValidateGatewayCIDRs(in []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if len(s) > maxCIDRLen {
			return nil, fmt.Errorf("invalid gateway CIDR %q", s)
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid gateway CIDR %q", s)
		}
		canon := n.String()
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		out = append(out, canon)
	}
	if len(out) > maxGatewayCIDRs {
		return nil, fmt.Errorf("pam_gateway_cidrs: max %d rules", maxGatewayCIDRs)
	}
	if out == nil {
		return []string{}, nil
	}
	sort.Strings(out)
	return out, nil
}

func GenerateIPTables(targets []ExportTarget, gateways []string) string {
	var b strings.Builder
	b.WriteString("# KeepPAM Firewall PAM — iptables\n")
	b.WriteString("# generated: " + time.Now().UTC().Format(time.RFC3339) + "\n")
	b.WriteString("# Apply on pam_only asset or upstream firewall.\n")
	if len(gateways) == 0 {
		b.WriteString("# WARNING: pam_gateway_cidrs empty — configure in Config → Firewall PAM.\n")
	}
	b.WriteByte('\n')
	for _, t := range targets {
		writeTargetHeader(&b, t)
		for _, cidr := range gateways {
			fmt.Fprintf(&b, "-A INPUT -p tcp -d %s --dport %d -s %s -j ACCEPT\n", t.Address, t.Port, cidr)
		}
		fmt.Fprintf(&b, "-A INPUT -p tcp -d %s --dport %d -j DROP\n", t.Address, t.Port)
		b.WriteByte('\n')
	}
	if len(targets) == 0 {
		b.WriteString("# No pam_only active assets.\n")
	}
	return b.String()
}

func GenerateNFT(targets []ExportTarget, gateways []string) string {
	var b strings.Builder
	b.WriteString("# KeepPAM Firewall PAM — nftables\n")
	b.WriteString("# generated: " + time.Now().UTC().Format(time.RFC3339) + "\n")
	if len(gateways) == 0 {
		b.WriteString("# WARNING: pam_gateway_cidrs empty — configure in Config → Firewall PAM.\n")
	}
	b.WriteString("table inet keeppam {\n")
	b.WriteString("\tchain forward_in {\n")
	b.WriteString("\t\ttype filter hook input priority 0; policy accept;\n")
	for _, t := range targets {
		writeTargetHeader(&b, t)
		for _, cidr := range gateways {
			fmt.Fprintf(&b, "\t\ttcp dport %d ip saddr %s ip daddr %s accept\n", t.Port, cidr, t.Address)
		}
		fmt.Fprintf(&b, "\t\ttcp dport %d ip daddr %s drop\n", t.Port, t.Address)
	}
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	if len(targets) == 0 {
		b.WriteString("# No pam_only active assets.\n")
	}
	return b.String()
}

func writeTargetHeader(b *strings.Builder, t ExportTarget) {
	fmt.Fprintf(b, "# Asset: %s (%s:%d %s)\n", t.Name, t.Address, t.Port, t.Protocol)
}

func GenerateAnsible(targets []ExportTarget, gateways []string) string {
	var b strings.Builder
	b.WriteString("# KeepPAM Firewall PAM — Ansible (iptables shell)\n")
	b.WriteString("# generated: " + time.Now().UTC().Format(time.RFC3339) + "\n")
	b.WriteString("---\n")
	b.WriteString("- name: KeepPAM pam_only perimeter rules\n")
	b.WriteString("  hosts: all\n")
	b.WriteString("  become: true\n")
	b.WriteString("  tasks:\n")
	if len(gateways) == 0 {
		b.WriteString("    # WARNING: pam_gateway_cidrs empty\n")
	}
	if len(targets) == 0 {
		b.WriteString("    - ansible.builtin.debug:\n")
		b.WriteString("        msg: no pam_only assets\n")
		return b.String()
	}
	for _, t := range targets {
		fmt.Fprintf(&b, "    - name: KeepPAM allow gateways to %s (%s:%d)\n", t.Name, t.Address, t.Port)
		b.WriteString("      ansible.builtin.shell: |\n")
		for _, cidr := range gateways {
			fmt.Fprintf(&b, "        iptables -A INPUT -p tcp -d %s --dport %d -s %s -j ACCEPT\n", t.Address, t.Port, cidr)
		}
		fmt.Fprintf(&b, "        iptables -A INPUT -p tcp -d %s --dport %d -j DROP\n", t.Address, t.Port)
		b.WriteString("      when: inventory_hostname == \"" + ansibleHost(t) + "\"\n")
	}
	return b.String()
}

func ansibleHost(t ExportTarget) string {
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-' || r == '_':
			return r
		default:
			return '-'
		}
	}, t.Name)
	if name == "" {
		return t.Address
	}
	return name
}
