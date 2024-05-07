package main

import (
	"encoding/json"
	"fmt"

	"github.com/shirou/gopsutil/disk"
)

type DiskUsage struct {
	Disk       string  `json:"disk"`
	MountPoint string  `json:"mount_point"`
	Total      uint64  `json:"total"`
	Free       uint64  `json:"free"`
	Used       uint64  `json:"used"`
	Usage      float64 `json:"usage"`
}

func getDiskUsage() (string, error) {
	partitions, err := disk.Partitions(true)
	if err != nil {
		fmt.Println("Failed to get disk partitions:", err)
		return "", err
	}
	var usages []DiskUsage
	for _, partition := range partitions {
		if partition.Mountpoint == "" {
			continue
		}
		if partition.Fstype != "ext4" && partition.Fstype != "xfs" && partition.Fstype != "btrfs" && partition.Fstype != "zfs" && partition.Fstype != "ext3" && partition.Fstype != "ext2" && partition.Fstype != "ntfs" && partition.Fstype != "fat32" && partition.Fstype != "exfat" {
			continue
		}

		usage, err := disk.Usage(partition.Mountpoint)
		if err != nil {
			fmt.Printf("Failed to get usage for partition %s: %s\n", partition.Mountpoint, err)
			continue
		}
		usages = append(usages, DiskUsage{
			Disk:       partition.Device,
			MountPoint: partition.Mountpoint,
			Total:      usage.Total,
			Free:       usage.Free,
			Used:       usage.Used,
			Usage:      usage.UsedPercent,
		})

	}
	jsonData, err := json.MarshalIndent(usages, "", "    ")
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}
