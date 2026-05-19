package tun

import (
	"net/netip"
	"testing"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

func TestAutoRedirectFallbackRulesExcludeICMP(t *testing.T) {
	const (
		tableIndex    = 2022
		ruleIndex     = 9000
		fallbackIndex = 32768
	)

	nativeTun := &NativeTun{
		options: Options{
			Inet4Address:                          []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
			Inet6Address:                          []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
			AutoRoute:                             true,
			IPRoute2TableIndex:                    tableIndex,
			IPRoute2RuleIndex:                     ruleIndex,
			IPRoute2AutoRedirectFallbackRuleIndex: fallbackIndex,
			AutoRedirectMarkMode:                  true,
			AutoRedirectInputMark:                 DefaultAutoRedirectInputMark,
			AutoRedirectOutputMark:                DefaultAutoRedirectOutputMark,
			ExcludeICMP:                           true,
		},
	}

	rules := nativeTun.rules()
	assertFallbackProtocolRules(t, rules, unix.AF_INET, fallbackIndex, tableIndex, []int{unix.IPPROTO_TCP, unix.IPPROTO_UDP})
	assertFallbackProtocolRules(t, rules, unix.AF_INET6, fallbackIndex, tableIndex, []int{unix.IPPROTO_TCP, unix.IPPROTO_UDP})
	assertNoFallbackProtocolRule(t, rules, unix.AF_INET, fallbackIndex, 0)
	assertNoFallbackProtocolRule(t, rules, unix.AF_INET6, fallbackIndex, 0)
	assertNoFallbackProtocolRule(t, rules, unix.AF_INET, fallbackIndex, unix.IPPROTO_ICMP)
	assertNoFallbackProtocolRule(t, rules, unix.AF_INET6, fallbackIndex, unix.IPPROTO_ICMPV6)
}

func TestAutoRedirectNonMarkModeRulesExcludeICMP(t *testing.T) {
	const (
		tableIndex = 2022
		ruleIndex  = 9000
	)

	nativeTun := &NativeTun{
		options: Options{
			Inet4Address:       []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
			Inet6Address:       []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
			AutoRoute:          true,
			IPRoute2TableIndex: tableIndex,
			IPRoute2RuleIndex:  ruleIndex,
			ExcludeICMP:        true,
		},
	}

	rules := nativeTun.rules()
	nopPriority := ruleIndex + 10
	assertExcludeProtocolRule(t, rules, unix.AF_INET, unix.IPPROTO_ICMP, nopPriority)
	assertExcludeProtocolRule(t, rules, unix.AF_INET6, unix.IPPROTO_ICMPV6, nopPriority)
}

func assertExcludeProtocolRule(t *testing.T, rules []*netlink.Rule, family int, ipProto int, expectedGoto int) {
	t.Helper()
	for _, rule := range rules {
		if rule.Family == family && rule.IPProto == ipProto && rule.Goto == expectedGoto {
			return
		}
	}
	t.Fatalf("expected exclude rule not found: family=%d ipproto=%d goto=%d", family, ipProto, expectedGoto)
}

func assertFallbackProtocolRules(t *testing.T, rules []*netlink.Rule, family int, priority int, table int, ipProtos []int) {
	t.Helper()
	for _, ipProto := range ipProtos {
		rule := findRule(t, rules, family, priority, ipProto)
		if rule.Table != table {
			t.Fatalf("unexpected fallback table: family=%d ipproto=%d table=%d", family, ipProto, rule.Table)
		}
		if !rule.Invert || !rule.MarkSet || rule.Mark != DefaultAutoRedirectOutputMark {
			t.Fatalf("fallback rule must skip packets carrying the output mark: family=%d ipproto=%d", family, ipProto)
		}
	}
}

func assertNoFallbackProtocolRule(t *testing.T, rules []*netlink.Rule, family int, priority int, ipProto int) {
	t.Helper()
	for _, rule := range rules {
		if rule.Family == family && rule.Priority == priority && rule.IPProto == ipProto {
			t.Fatalf("unexpected fallback rule: family=%d ipproto=%d", family, ipProto)
		}
	}
}

func findRule(t *testing.T, rules []*netlink.Rule, family int, priority int, ipProto int) *netlink.Rule {
	t.Helper()
	for _, rule := range rules {
		if rule.Family == family && rule.Priority == priority && rule.IPProto == ipProto {
			return rule
		}
	}
	t.Fatalf("rule not found: family=%d priority=%d ipproto=%d", family, priority, ipProto)
	return nil
}
