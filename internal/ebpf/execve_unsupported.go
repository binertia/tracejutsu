//go:build !linux || (!amd64 && !arm64)

package ebpf

import (
	"context"
	"errors"

	"tracejutsu/internal/events"
)

type ExecveCollector struct{}
type ConnectCollector struct{}
type FileWriteCollector struct{}
type ChmodCollector struct{}
type SensitiveReadCollector struct{}
type FileLifecycleCollector struct{}
type BehaviorSyscallCollector struct{}
type NetworkServerCollector struct{}

func NewExecveCollector() (*ExecveCollector, error) {
	return nil, errors.New("live execve collection currently requires Linux amd64 or arm64")
}

func NewExecveCollectorWithConfig(RuntimeConfig) (*ExecveCollector, error) {
	return nil, errors.New("live execve collection currently requires Linux amd64 or arm64")
}

func (*ExecveCollector) Run(context.Context, chan<- events.Event) error {
	return errors.New("live execve collection currently requires Linux amd64 or arm64")
}

func NewConnectCollector() (*ConnectCollector, error) {
	return nil, errors.New("live connect collection currently requires Linux amd64 or arm64")
}

func NewConnectCollectorWithConfig(RuntimeConfig) (*ConnectCollector, error) {
	return nil, errors.New("live connect collection currently requires Linux amd64 or arm64")
}

func (*ConnectCollector) Run(context.Context, chan<- events.Event) error {
	return errors.New("live connect collection currently requires Linux amd64 or arm64")
}

func NewFileWriteCollector() (*FileWriteCollector, error) {
	return nil, errors.New("live file write collection currently requires Linux amd64 or arm64")
}

func NewFileWriteCollectorWithConfig(RuntimeConfig) (*FileWriteCollector, error) {
	return nil, errors.New("live file write collection currently requires Linux amd64 or arm64")
}

func (*FileWriteCollector) Run(context.Context, chan<- events.Event) error {
	return errors.New("live file write collection currently requires Linux amd64 or arm64")
}

func NewChmodCollector() (*ChmodCollector, error) {
	return nil, errors.New("live chmod collection currently requires Linux amd64 or arm64")
}

func NewChmodCollectorWithConfig(RuntimeConfig) (*ChmodCollector, error) {
	return nil, errors.New("live chmod collection currently requires Linux amd64 or arm64")
}

func (*ChmodCollector) Run(context.Context, chan<- events.Event) error {
	return errors.New("live chmod collection currently requires Linux amd64 or arm64")
}

func NewSensitiveReadCollector() (*SensitiveReadCollector, error) {
	return nil, errors.New("live sensitive read collection currently requires Linux amd64 or arm64")
}

func NewSensitiveReadCollectorWithConfig(RuntimeConfig) (*SensitiveReadCollector, error) {
	return nil, errors.New("live sensitive read collection currently requires Linux amd64 or arm64")
}

func (*SensitiveReadCollector) Run(context.Context, chan<- events.Event) error {
	return errors.New("live sensitive read collection currently requires Linux amd64 or arm64")
}

func NewFileLifecycleCollector() (*FileLifecycleCollector, error) {
	return nil, errors.New("live file lifecycle collection currently requires Linux amd64 or arm64")
}

func NewFileLifecycleCollectorWithConfig(RuntimeConfig) (*FileLifecycleCollector, error) {
	return nil, errors.New("live file lifecycle collection currently requires Linux amd64 or arm64")
}

func (*FileLifecycleCollector) Run(context.Context, chan<- events.Event) error {
	return errors.New("live file lifecycle collection currently requires Linux amd64 or arm64")
}

func NewPrivilegeChangeCollector() (*BehaviorSyscallCollector, error) {
	return nil, errors.New("live privilege change collection currently requires Linux amd64 or arm64")
}

func NewPrivilegeChangeCollectorWithConfig(RuntimeConfig) (*BehaviorSyscallCollector, error) {
	return nil, errors.New("live privilege change collection currently requires Linux amd64 or arm64")
}

func NewNamespaceChangeCollector() (*BehaviorSyscallCollector, error) {
	return nil, errors.New("live namespace change collection currently requires Linux amd64 or arm64")
}

func NewNamespaceChangeCollectorWithConfig(RuntimeConfig) (*BehaviorSyscallCollector, error) {
	return nil, errors.New("live namespace change collection currently requires Linux amd64 or arm64")
}

func NewProcessAccessCollector() (*BehaviorSyscallCollector, error) {
	return nil, errors.New("live process access collection currently requires Linux amd64 or arm64")
}

func NewProcessAccessCollectorWithConfig(RuntimeConfig) (*BehaviorSyscallCollector, error) {
	return nil, errors.New("live process access collection currently requires Linux amd64 or arm64")
}

func NewKernelTamperCollector() (*BehaviorSyscallCollector, error) {
	return nil, errors.New("live kernel tamper collection currently requires Linux amd64 or arm64")
}

func NewKernelTamperCollectorWithConfig(RuntimeConfig) (*BehaviorSyscallCollector, error) {
	return nil, errors.New("live kernel tamper collection currently requires Linux amd64 or arm64")
}

func (*BehaviorSyscallCollector) Run(context.Context, chan<- events.Event) error {
	return errors.New("live behavior syscall collection currently requires Linux amd64 or arm64")
}

func NewNetworkServerCollector() (*NetworkServerCollector, error) {
	return nil, errors.New("live network server collection currently requires Linux amd64 or arm64")
}

func NewNetworkServerCollectorWithConfig(RuntimeConfig) (*NetworkServerCollector, error) {
	return nil, errors.New("live network server collection currently requires Linux amd64 or arm64")
}

func (*NetworkServerCollector) Run(context.Context, chan<- events.Event) error {
	return errors.New("live network server collection currently requires Linux amd64 or arm64")
}

func NewRuntimeCollector() (Collector, error) {
	return nil, errors.New("live collection currently requires Linux amd64 or arm64")
}

func NewRuntimeCollectorWithConfig(config RuntimeConfig) (Collector, error) {
	if _, err := checkedRuntimeConfig(config); err != nil {
		return nil, err
	}
	if _, err := checkedCollectorNames(config.Collectors); err != nil {
		return nil, err
	}
	return nil, errors.New("live collection currently requires Linux amd64 or arm64")
}
