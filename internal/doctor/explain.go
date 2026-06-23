package doctor

import (
	"fmt"
	"strings"
)

type Domain string

const (
	DomainRouting   Domain = "routing"
	DomainFirewall  Domain = "firewall"
	DomainConntrack Domain = "conntrack"
	DomainQdisc     Domain = "qdisc"
	DomainSocket    Domain = "socket"
	DomainDriver    Domain = "driver"
	DomainUnknown   Domain = "unknown"
)

type Explanation struct {
	ReasonName string   `json:"reason_name"`
	Domain     Domain   `json:"domain"`
	Summary    string   `json:"summary"`
	Checks     []string `json:"checks"`
}

// ReasonName is intentionally conservative. skb_drop_reason numeric values can
// differ across kernel versions as the enum evolves. For production use, load a
// generated map from the target kernel's BTF. See docs/drop-reason-map.md.
func ReasonName(reason uint32) string {
	known := map[uint32]string{
		0:  "NOT_DROPPED_YET",
		1:  "NOT_SPECIFIED",
		2:  "NO_SOCKET",
		3:  "PKT_TOO_SMALL",
		4:  "TCP_CSUM",
		5:  "SOCKET_FILTER",
		6:  "UDP_CSUM",
		7:  "NETFILTER_DROP",
		8:  "OTHERHOST",
		9:  "IP_CSUM",
		10: "IP_INHDR",
		11: "IP_RPFILTER",
		12: "UNICAST_IN_L2_MULTICAST",
		13: "XFRM_POLICY",
		14: "IP_NOPROTO",
		15: "SOCKET_RCVBUFF",
		16: "PROTO_MEM",
		17: "TCP_MD5NOTFOUND",
		18: "TCP_MD5UNEXPECTED",
		19: "TCP_MD5FAILURE",
		20: "SOCKET_BACKLOG",
		21: "TCP_FLAGS",
		22: "TCP_ZEROWINDOW",
		23: "TCP_OLD_DATA",
		24: "TCP_OVERWINDOW",
	}
	if name, ok := known[reason]; ok {
		return name
	}
	return fmt.Sprintf("SKB_DROP_REASON_%d", reason)
}

func Explain(e Event) Explanation {
	name := ReasonName(e.Reason)
	upper := strings.ToUpper(name)

	switch {
	case strings.Contains(upper, "NETFILTER") || strings.Contains(upper, "NF_") || strings.Contains(upper, "FIREWALL"):
		return Explanation{
			ReasonName: name,
			Domain:     DomainFirewall,
			Summary:    "netfilter/nftables/iptables 계층에서 DROP verdict가 발생했을 가능성이 큽니다.",
			Checks: []string{
				"sudo nft list ruleset",
				"sudo iptables-save",
				"sudo conntrack -S",
			},
		}
	case strings.Contains(upper, "CONNTRACK") || strings.Contains(upper, "CT_"):
		return Explanation{
			ReasonName: name,
			Domain:     DomainConntrack,
			Summary:    "conntrack table, state validation, NAT state 불일치로 drop되었을 가능성이 큽니다.",
			Checks: []string{
				"sudo conntrack -S",
				"sudo conntrack -L | head",
				"sysctl net.netfilter.nf_conntrack_max net.netfilter.nf_conntrack_count",
			},
		}
	case strings.Contains(upper, "NO_ROUTE") || strings.Contains(upper, "ROUTE") || strings.Contains(upper, "RPFILTER") || strings.Contains(upper, "IP_") || strings.Contains(upper, "XFRM"):
		return Explanation{
			ReasonName: name,
			Domain:     DomainRouting,
			Summary:    "라우팅 테이블, reverse path filter, 정책 라우팅 또는 IPsec/XFRM 정책 문제일 수 있습니다.",
			Checks: []string{
				"ip route get <dst>",
				"ip rule show",
				"sysctl net.ipv4.conf.all.rp_filter",
			},
		}
	case strings.Contains(upper, "QDISC") || strings.Contains(upper, "TC_") || strings.Contains(upper, "QUEUE"):
		return Explanation{
			ReasonName: name,
			Domain:     DomainQdisc,
			Summary:    "qdisc, tc filter, queue overflow 또는 egress shaping 과정에서 drop되었을 수 있습니다.",
			Checks: []string{
				"tc -s qdisc show dev <iface>",
				"tc -s filter show dev <iface> ingress",
				"tc -s filter show dev <iface> egress",
			},
		}
	case strings.Contains(upper, "SOCKET") || strings.Contains(upper, "TCP") || strings.Contains(upper, "UDP"):
		return Explanation{
			ReasonName: name,
			Domain:     DomainSocket,
			Summary:    "소켓 수신 버퍼, checksum, TCP state, backlog 또는 socket filter 문제일 수 있습니다.",
			Checks: []string{
				"ss -s",
				"ss -tinp",
				"netstat -s | egrep -i 'drop|error|checksum|reset'",
			},
		}
	case strings.Contains(upper, "DRIVER") || strings.Contains(upper, "DEV") || strings.Contains(upper, "XDP"):
		return Explanation{
			ReasonName: name,
			Domain:     DomainDriver,
			Summary:    "NIC driver, XDP, device queue 또는 MTU 관련 drop일 수 있습니다.",
			Checks: []string{
				"ip -s link show dev <iface>",
				"ethtool -S <iface>",
				"ip link show dev <iface>",
			},
		}
	default:
		return Explanation{
			ReasonName: name,
			Domain:     DomainUnknown,
			Summary:    "커널 reason map 또는 location symbolization을 추가로 확인해야 합니다.",
			Checks: []string{
				"sudo cat /proc/kallsyms | grep <location>",
				"bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep skb_drop_reason -A120",
			},
		}
	}
}
