package guacd

import (
	"net"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	if Parse("") != nil || Parse("off") != nil {
		t.Fatal("off")
	}
	got := Parse(" guacd:4822 , g2:4822,off, ")
	if len(got) != 2 || got[0] != "guacd:4822" || got[1] != "g2:4822" {
		t.Fatalf("%v", got)
	}
}

func TestDialRoundRobinSkipDead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	addrs := []string{"127.0.0.1:1", ln.Addr().String()}
	c, err := Dial(addrs, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

func TestDialEmpty(t *testing.T) {
	_, err := Dial(nil, time.Millisecond)
	if err == nil {
		t.Fatal("expected error")
	}
}
