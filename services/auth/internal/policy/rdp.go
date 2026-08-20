package policy

// RDPRedir holds Guacamole / native RDP channel policy (default all off = DLP-strict).
type RDPRedir struct {
	Clipboard bool `json:"rdp_clipboard"`
	Drive     bool `json:"rdp_drive"`
	Printer   bool `json:"rdp_printer"`
	Native    bool `json:"rdp_native"`
}

func (sn *Snapshot) RDP() RDPRedir {
	if sn == nil {
		return RDPRedir{}
	}
	return RDPRedir{
		Clipboard: sn.RDPClipboard,
		Drive:     sn.RDPDrive,
		Printer:   sn.RDPPrinter,
		Native:    sn.RDPNative,
	}
}
