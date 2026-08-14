package policy

import "context"

type devicesKey struct{}

func WithDevices(ctx context.Context, devices []string) context.Context {
	if len(devices) == 0 {
		return ctx
	}
	return context.WithValue(ctx, devicesKey{}, devices)
}

func DevicesFrom(ctx context.Context) []string {
	d, _ := ctx.Value(devicesKey{}).([]string)
	return d
}
