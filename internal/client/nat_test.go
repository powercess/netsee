package client

import "testing"

// TestNatJudgment locks the NAT label semantics discovered against a real
// network (P4): the same socket keeping one external port across two
// destinations is CONE behavior, not symmetric.
func TestNatJudgment(t *testing.T) {
	cases := []struct {
		name                string
		localIP, observedIP string
		p1, p2              int
		r3, secondIP, r4    bool
		want                string
	}{
		{"direct no-NAT", "1.2.3.4", "1.2.3.4", 1000, 1000, true, false, false, "直连（无 NAT 翻译）"},
		{"symmetric mapping", "10.0.0.5", "1.2.3.4", 1000, 2000, true, false, false, "对称式映射"},
		{"cone port-filtered", "10.0.0.5", "1.2.3.4", 1000, 1000, false, false, false, "端口受限锥形"},
		{"cone open", "10.0.0.5", "1.2.3.4", 1000, 1000, true, false, false, "锥形（端口不过滤）"},
		{"addr-restricted", "10.0.0.5", "1.2.3.4", 1000, 1000, true, true, false, "地址受限锥形"},
		{"cone open even with second-ip", "10.0.0.5", "1.2.3.4", 1000, 1000, true, true, true, "锥形（端口不过滤）"},
	}
	for _, tc := range cases {
		label, _, _ := natJudgment(tc.localIP, tc.observedIP, tc.p1, tc.p2, tc.r3, tc.secondIP, tc.r4)
		if label != tc.want {
			t.Errorf("%s: label = %q, want %q", tc.name, label, tc.want)
		}
	}
}
