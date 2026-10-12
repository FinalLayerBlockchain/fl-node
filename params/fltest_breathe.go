//go:build fltest

package params

// Test-only build (go build -tags fltest): breathe blocks every 10 minutes so
// the daily staking inflation and validator election can be exercised on a
// devnet. Never used in release binaries.
func init() {
	BreatheBlockInterval = 600
}
