package pcapx

import (
	"bytes"
	"encoding/binary"
	"io"
)

const (
	magicMicro = 0xa1b2c3d4
	versionMaj = 2
	versionMin = 4
	snapLen    = 65535
	linkEth    = 1
	maxPayload = 1400
)

// WriteStream wraps payload as a unidirectional TCP stream in a pcap
// (Ethernet + IPv4 + TCP). Wireshark can Follow TCP Stream the bytes.
func WriteStream(w io.Writer, payload []byte) error {
	return WriteStreamFrom(w, bytes.NewReader(payload))
}

// WriteStreamFrom is the streaming form of WriteStream.
func WriteStreamFrom(w io.Writer, r io.Reader) error {
	if err := writeGlobal(w); err != nil {
		return err
	}
	buf := make([]byte, maxPayload)
	seq := uint32(1)
	ts := uint32(0)
	wrote := false
	for {
		n, err := r.Read(buf)
		if n > 0 {
			wrote = true
			if werr := writePacket(w, ts, dummyFrame(buf[:n], seq, false)); werr != nil {
				return werr
			}
			seq += uint32(n)
			ts++
		}
		if err == io.EOF {
			if !wrote {
				return writePacket(w, 0, dummyFrame(nil, 0, true))
			}
			return writePacket(w, ts, dummyFrame(nil, seq, true))
		}
		if err != nil {
			return err
		}
	}
}

func writeGlobal(w io.Writer) error {
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], magicMicro)
	binary.LittleEndian.PutUint16(hdr[4:6], versionMaj)
	binary.LittleEndian.PutUint16(hdr[6:8], versionMin)
	binary.LittleEndian.PutUint32(hdr[16:20], snapLen)
	binary.LittleEndian.PutUint32(hdr[20:24], linkEth)
	_, err := w.Write(hdr[:])
	return err
}

func writePacket(w io.Writer, tsSec uint32, frame []byte) error {
	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[0:4], tsSec)
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(frame)))
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(frame)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(frame)
	return err
}

func dummyFrame(payload []byte, seq uint32, fin bool) []byte {
	return dummyFrameEx(payload, seq, fin, true, 4822, 3389)
}

func dummyFrameEx(payload []byte, seq uint32, fin, c2s bool, srcPort, dstPort uint16) []byte {
	srcMAC := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	srcIP := []byte{10, 0, 0, 1}
	dstIP := []byte{10, 0, 0, 2}
	sp, dp := srcPort, dstPort
	if !c2s {
		srcMAC, dstMAC = dstMAC, srcMAC
		srcIP, dstIP = dstIP, srcIP
		sp, dp = dstPort, srcPort
	}

	eth := make([]byte, 14)
	copy(eth[0:6], dstMAC)
	copy(eth[6:12], srcMAC)
	eth[12], eth[13] = 0x08, 0x00

	ipLen := 20 + 20 + len(payload)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], srcIP)
	copy(ip[16:20], dstIP)
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], sp)
	binary.BigEndian.PutUint16(tcp[2:4], dp)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 5 << 4
	flags := byte(0x18) // PSH+ACK
	if fin {
		flags |= 0x01
	}
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)

	out := make([]byte, 0, 14+20+20+len(payload))
	out = append(out, eth...)
	out = append(out, ip...)
	out = append(out, tcp...)
	out = append(out, payload...)
	return out
}

func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
