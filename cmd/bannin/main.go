// Command bannin is the entry point for the BANNIN DevSecOps orchestration
// platform CLI. Milestone 2: Cobra wiring (`bannin scan`, `bannin version`)
// lives in this package; it stays free of orchestration logic, which is
// added milestone-by-milestone in internal/.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
