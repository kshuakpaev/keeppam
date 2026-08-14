package siem

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"

	"github.com/keeppam/auth/internal/store"
)

func splitBrokers(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Service) sendKafka(ctx context.Context, cfg Settings, password string, events []store.AuditEvent) error {
	brokers := splitBrokers(cfg.KafkaBrokers)
	topic := strings.TrimSpace(cfg.KafkaTopic)
	if len(brokers) == 0 {
		return fmt.Errorf("kafka_brokers required")
	}
	if topic == "" {
		return fmt.Errorf("kafka_topic required")
	}
	w := &kafka.Writer{
		Addr:                   kafka.TCP(brokers...),
		Topic:                  topic,
		Balancer:               &kafka.LeastBytes{},
		AllowAutoTopicCreation: true,
		BatchTimeout:           50 * time.Millisecond,
		WriteTimeout:           15 * time.Second,
	}
	user := strings.TrimSpace(cfg.KafkaUsername)
	if user != "" {
		w.Transport = &kafka.Transport{
			SASL: plain.Mechanism{Username: user, Password: password},
		}
	}
	defer w.Close()

	msgs := make([]kafka.Message, 0, len(events))
	for _, e := range events {
		msgs = append(msgs, kafka.Message{
			Key:   []byte(e.ID.String()),
			Value: []byte(formatEvent(cfg.Format, e)),
			Time:  e.TS.UTC(),
		})
	}
	c, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return w.WriteMessages(c, msgs...)
}

func (s *Service) sendNATS(ctx context.Context, cfg Settings, token string, events []store.AuditEvent) error {
	url := strings.TrimSpace(cfg.NATSURL)
	subj := strings.TrimSpace(cfg.NATSSubject)
	if url == "" {
		return fmt.Errorf("nats_url required")
	}
	if subj == "" {
		return fmt.Errorf("nats_subject required")
	}
	opts := []nats.Option{
		nats.Name("keeppam-siem"),
		nats.Timeout(5 * time.Second),
	}
	if token != "" {
		opts = append(opts, nats.Token(token))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return err
	}
	defer nc.Close()
	for _, e := range events {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := nc.Publish(subj, []byte(formatEvent(cfg.Format, e))); err != nil {
			return err
		}
	}
	return nc.FlushTimeout(5 * time.Second)
}
