package citrix

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ICAFileOpts builds a Citrix Workspace / ICA client connect file that tunnels via KeepPAM SOCKS.
type ICAFileOpts struct {
	ProxyHost     string // public PAM host for SOCKS
	ProxyPort     int    // e.g. 1081
	ProxyUser     string // session UUID
	ProxyPassword string // wire token
	TargetHost    string // VDA / XenApp address
	TargetPort    int    // ICA port, default 1494
	AppName       string // section name
	InitialProg   string // optional #App
	Title         string
}

// BuildICAFile returns an .ica body (INI). ProxyType=Socks — путь как у SPS/Fudo SOCKS mode.
func BuildICAFile(o ICAFileOpts) string {
	if o.ProxyPort <= 0 {
		o.ProxyPort = 1081
	}
	if o.TargetPort <= 0 {
		o.TargetPort = 1494
	}
	if o.AppName == "" {
		o.AppName = "KeepPAM"
	}
	safe := sanitizeSection(o.AppName)
	addr := o.TargetHost
	if o.TargetPort != 1494 {
		addr = net.JoinHostPort(o.TargetHost, strconv.Itoa(o.TargetPort))
	}
	var b strings.Builder
	b.WriteString("[Encoding]\r\nInputEncoding=UTF8\r\n\r\n")
	b.WriteString("[WFClient]\r\nVersion=2\r\n")
	b.WriteString("ProxyType=Socks\r\n")
	b.WriteString(fmt.Sprintf("ProxyHost=%s\r\n", o.ProxyHost))
	b.WriteString(fmt.Sprintf("ProxyPort=%d\r\n", o.ProxyPort))
	b.WriteString(fmt.Sprintf("ProxyUsername=%s\r\n", o.ProxyUser))
	b.WriteString(fmt.Sprintf("ProxyPassword=%s\r\n", o.ProxyPassword))
	b.WriteString("\r\n[ApplicationServers]\r\n")
	b.WriteString(fmt.Sprintf("%s=\r\n\r\n", safe))
	b.WriteString(fmt.Sprintf("[%s]\r\n", safe))
	b.WriteString(fmt.Sprintf("Address=%s\r\n", addr))
	b.WriteString("TransportDriver=TCP/IP\r\n")
	b.WriteString("WinStationDriver=ICA 3.0\r\n")
	b.WriteString("CGPAddress=*:2598\r\n")
	b.WriteString("BrowserProtocol=HTTPonTCP\r\n")
	if o.Title != "" {
		b.WriteString(fmt.Sprintf("Title=%s\r\n", o.Title))
	}
	if o.InitialProg != "" {
		b.WriteString(fmt.Sprintf("InitialProgram=%s\r\n", o.InitialProg))
	}
	b.WriteString("AutologonAllowed=ON\r\n")
	return b.String()
}

func sanitizeSection(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "KeepPAM"
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return "KeepPAM"
	}
	return string(out)
}
