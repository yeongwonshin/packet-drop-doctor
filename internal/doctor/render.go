package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"text/tabwriter"
)

type Renderer struct {
	w       io.Writer
	ifaceBy map[uint32]string
	json    bool
	explain bool
}

func NewRenderer(w io.Writer, jsonOutput bool, explain bool) *Renderer {
	return &Renderer{w: w, json: jsonOutput, explain: explain, ifaceBy: loadIfaces()}
}

func loadIfaces() map[uint32]string {
	out := map[uint32]string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		out[uint32(iface.Index)] = iface.Name
	}
	return out
}

func (r *Renderer) ifaceName(idx uint32) string {
	if idx == 0 {
		return "-"
	}
	if name, ok := r.ifaceBy[idx]; ok {
		return name
	}
	return fmt.Sprintf("if%d", idx)
}

func (r *Renderer) PrintHeader() {
	if r.json {
		return
	}
	if r.explain {
		fmt.Fprintln(r.w, "TIME\tIFACE\tFLOW\tREASON\tWHERE\tWHY")
		return
	}
	fmt.Fprintln(r.w, "TIME\tIFACE\tFLOW\tREASON\tLOCATION\tCOMM")
}

func (r *Renderer) PrintEvent(e Event) error {
	if r.json {
		payload := struct {
			Event       Event       `json:"event"`
			Interface   string      `json:"interface"`
			Flow        string      `json:"flow"`
			Explanation Explanation `json:"explanation,omitempty"`
		}{Event: e, Interface: r.ifaceName(e.Ifindex), Flow: e.Flow()}
		if r.explain {
			payload.Explanation = Explain(e)
		}
		return json.NewEncoder(r.w).Encode(payload)
	}

	exp := Explain(e)
	if r.explain {
		fmt.Fprintf(r.w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			e.Time().Format("15:04:05"), r.ifaceName(e.Ifindex), e.Flow(), exp.ReasonName, exp.Domain, exp.Summary)
		return nil
	}

	fmt.Fprintf(r.w, "%s\t%s\t%s\t%s\t0x%x\t%s\n",
		e.Time().Format("15:04:05"), r.ifaceName(e.Ifindex), e.Flow(), exp.ReasonName, e.Location, e.CommString())
	return nil
}

type Aggregate struct {
	Packets uint64
	Bytes   uint64
	Sample  Event
}

func PrintTop(w io.Writer, aggs []*Aggregate) {
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "PACKETS\tBYTES\tIFACE\tPROTO\tREASON\tDOMAIN\tSAMPLE_FLOW")
	for _, agg := range aggs {
		exp := Explain(agg.Sample)
		fmt.Fprintf(tw, "%d\t%d\tif%d\t%s\t%s\t%s\t%s\n",
			agg.Packets, agg.Bytes, agg.Sample.Ifindex, agg.Sample.L4ProtoName(), exp.ReasonName, exp.Domain, agg.Sample.Flow())
	}
	_ = tw.Flush()
}
