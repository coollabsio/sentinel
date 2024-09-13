package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sentinel/pkg/db"
	"time"

	"github.com/shirou/gopsutil/disk"
)

type DiskUsage struct {
	Time       string `json:"time"`
	Disk       string `json:"disk"`
	MountPoint string `json:"mount_point"`
	Total      uint64 `json:"total"`
	Free       uint64 `json:"free"`
	Used       uint64 `json:"used"`
	Usage      string `json:"usage"`
}

var diskCsvHeader = "time,disk,mount_point,total,free,usage_percent\n"

func CollectDiskUsage() {

	partitions, err := disk.Partitions(true)
	queryTimeInUnixString := getUnixTimeInMilliUTC()
	if err != nil {
		log.Printf("%v", err)
		return
	}
	var usages []DiskUsage
	for _, partition := range partitions {
		if partition.Mountpoint == "" {
			continue
		}
		if partition.Mountpoint != "/" {
			if partition.Fstype != "ext4" && partition.Fstype != "xfs" && partition.Fstype != "btrfs" && partition.Fstype != "zfs" && partition.Fstype != "ext3" && partition.Fstype != "ext2" && partition.Fstype != "ntfs" && partition.Fstype != "fat32" && partition.Fstype != "exfat" {
				continue
			}
		}

		usage, err := disk.Usage(partition.Mountpoint)
		if err != nil {
			fmt.Printf("Failed to get usage for partition %s: %s\n", partition.Mountpoint, err)
			continue
		}
		usedPercentage := fmt.Sprintf("%.1f", usage.UsedPercent)
		usages = append(usages, DiskUsage{
			Time:       queryTimeInUnixString,
			Disk:       partition.Device,
			MountPoint: partition.Mountpoint,
			Total:      usage.Total,
			Free:       usage.Free,
			Used:       usage.Used,
			Usage:      usedPercentage,
		})
		db.Write("disk", int(time.Now().Unix()), usages)
	}
}

func getDiskUsage(csv bool) (string, error) {
	partitions, err := disk.Partitions(true)
	queryTimeInUnixString := getUnixTimeInMilliUTC()
	if err != nil {
		fmt.Println("Failed to get disk partitions:", err)
		return "", err
	}
	var usages []DiskUsage
	for _, partition := range partitions {
		if partition.Mountpoint == "" {
			continue
		}
		if partition.Mountpoint != "/" {
			if partition.Fstype != "ext4" && partition.Fstype != "xfs" && partition.Fstype != "btrfs" && partition.Fstype != "zfs" && partition.Fstype != "ext3" && partition.Fstype != "ext2" && partition.Fstype != "ntfs" && partition.Fstype != "fat32" && partition.Fstype != "exfat" {
				continue
			}
		}

		usage, err := disk.Usage(partition.Mountpoint)
		if err != nil {
			fmt.Printf("Failed to get usage for partition %s: %s\n", partition.Mountpoint, err)
			continue
		}
		usedPercentage := fmt.Sprintf("%.1f", usage.UsedPercent)
		usages = append(usages, DiskUsage{
			Time:       queryTimeInUnixString,
			Disk:       partition.Device,
			MountPoint: partition.Mountpoint,
			Total:      usage.Total,
			Free:       usage.Free,
			Used:       usage.Used,
			Usage:      usedPercentage,
		})
	}
	jsonData, err := json.MarshalIndent(usages, "", "    ")
	if err != nil {
		return "", err
	}
	if csv {
		var csvData string
		for _, usage := range usages {
			csvData += fmt.Sprintf("%s,%s,%s,%d,%d,%s\n", usage.Time, usage.Disk, usage.MountPoint, usage.Total, usage.Free, usage.Usage)
		}
		return csvData, nil
	}

	return string(jsonData), nil
}
