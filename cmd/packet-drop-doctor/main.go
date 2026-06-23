package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/spf13/cobra"

	"github.com/example/packet-drop-doctor/internal/doctor"
	"github.com/example/packet-drop-doctor/internal/loader"
)

type runOptions struct {
	duration time.Duration
	iface    string
	json     bool
	explain  bool
}

func main() {
	root := &cobra.Command{
		Use:   "packet-drop-doctor",
		Short: "Explain why Linux packets are dropped using eBPF",
	}

	var traceOpts runOptions
	traceCmd := &cobra.Command{
		Use:   "trace",
		Short: "Stream packet drop events",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrace(cmd.Context(), traceOpts)
		},
	}
	traceCmd.Flags().DurationVar(&traceOpts.duration, "duration", 0, "capture duration, e.g. 30s; 0 means until Ctrl-C")
	traceCmd.Flags().StringVar(&traceOpts.iface, "iface", "", "interface name filter")
	traceCmd.Flags().BoolVar(&traceOpts.json, "json", false, "emit JSON lines")
	traceCmd.Flags().BoolVar(&traceOpts.explain, "explain", false, "include human-readable reason explanation")

	var topOpts runOptions
	topCmd := &cobra.Command{
		Use:   "top",
		Short: "Aggregate packet drops by reason/interface/protocol",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTop(cmd.Context(), topOpts)
		},
	}
	topCmd.Flags().DurationVar(&topOpts.duration, "duration", 30*time.Second, "capture duration")
	topCmd.Flags().StringVar(&topOpts.iface, "iface", "", "interface name filter")

	explainCmd := &cobra.Command{
		Use:   "explain <reason-number>",
		Short: "Explain a drop reason number using the built-in heuristic map",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var reason uint32
			if _, err := fmt.Sscanf(args[0], "%d", &reason); err != nil {
				return fmt.Errorf("reason must be a number: %w", err)
			}
			e := doctor.Event{Reason: reason}
			exp := doctor.Explain(e)
			fmt.Printf("Reason: %s\nDomain: %s\nSummary: %s\n", exp.ReasonName, exp.Domain, exp.Summary)
			fmt.Println("Suggested checks:")
			for _, check := range exp.Checks {
				fmt.Printf("  - %s\n", check)
			}
			return nil
		},
	}

	root.AddCommand(traceCmd, topCmd, explainCmd)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func contextWithDuration(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, d)
}

func ifaceIndex(name string) (uint32, error) {
	if name == "" {
		return 0, nil
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return uint32(iface.Index), nil
}

func openReader(rt *loader.Runtime, ctx context.Context) (*ringbuf.Reader, error) {
	rd, err := ringbuf.NewReader(rt.Objects.Events)
	if err != nil {
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()
	return rd, nil
}

func runTrace(parent context.Context, opts runOptions) error {
	ctx, cancel := contextWithDuration(parent, opts.duration)
	defer cancel()

	filterIf, err := ifaceIndex(opts.iface)
	if err != nil {
		return fmt.Errorf("resolve iface %q: %w", opts.iface, err)
	}

	rt, err := loader.New()
	if err != nil {
		return err
	}
	defer rt.Close()

	rd, err := openReader(rt, ctx)
	if err != nil {
		return err
	}
	defer rd.Close()

	renderer := doctor.NewRenderer(os.Stdout, opts.json, opts.explain)
	renderer.PrintHeader()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read ringbuf: %w", err)
		}
		e, err := doctor.DecodeEvent(record.RawSample)
		if err != nil {
			return err
		}
		if filterIf != 0 && e.Ifindex != filterIf {
			continue
		}
		if err := renderer.PrintEvent(e); err != nil {
			return err
		}
	}
}

func runTop(parent context.Context, opts runOptions) error {
	ctx, cancel := contextWithDuration(parent, opts.duration)
	defer cancel()

	filterIf, err := ifaceIndex(opts.iface)
	if err != nil {
		return fmt.Errorf("resolve iface %q: %w", opts.iface, err)
	}

	rt, err := loader.New()
	if err != nil {
		return err
	}
	defer rt.Close()

	rd, err := openReader(rt, ctx)
	if err != nil {
		return err
	}
	defer rd.Close()

	aggs := map[string]*doctor.Aggregate{}
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				break
			}
			return fmt.Errorf("read ringbuf: %w", err)
		}
		e, err := doctor.DecodeEvent(record.RawSample)
		if err != nil {
			return err
		}
		if filterIf != 0 && e.Ifindex != filterIf {
			continue
		}
		key := fmt.Sprintf("%d/%d/%d", e.Reason, e.Ifindex, e.L4Proto)
		if aggs[key] == nil {
			aggs[key] = &doctor.Aggregate{Sample: e}
		}
		aggs[key].Packets++
		aggs[key].Bytes += uint64(e.Len)
	}

	sorted := sortAggs(aggs)
	doctor.PrintTop(os.Stdout, sorted)
	return nil
}

func sortAggs(in map[string]*doctor.Aggregate) []*doctor.Aggregate {
	out := make([]*doctor.Aggregate, 0, len(in))
	for _, agg := range in {
		out = append(out, agg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Packets > out[j].Packets })
	return out
}
