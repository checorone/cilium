// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/vtep"
)

const (
	vtepUpdateUsage = "Create/Update vtep entry.\n"
)

var bpfVtepUpdateCmd = &cobra.Command{
	Args:    cobra.ExactArgs(3),
	Use:     "update",
	Short:   "Update vtep entries",
	Aliases: []string{"add"},
	Long:    vtepUpdateUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf vtep update <vtep_cidr> <vtep_ip> <vtep_mac>")

		vcidr, err := cidr.ParseCIDR(args[0])
		if err != nil {
			Fatalf("error parsing cidr %s: %s", args[0], err)
		}

		vni, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil {
			Fatalf("error parsing vni %s: %s", args[1], err)
		}

		vip := net.ParseIP(args[2]).To4()
		if vip == nil {
			Fatalf("Unable to parse IP '%s'", args[3])
		}

		vmac, err := mac.ParseMAC(args[3])
		if err != nil {
			Fatalf("Unable to parse vtep mac '%s'", args[3])
		}

		if err := vtep.UpdateVTEPMapping(vcidr, uint32(vni), vip, vmac); err != nil {
			fmt.Fprintf(os.Stderr, "error updating contents of map: %s\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	BPFVtepCmd.AddCommand(bpfVtepUpdateCmd)
}
