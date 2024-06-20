package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
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
		if partition.Fstype != "ext4" && partition.Fstype != "xfs" && partition.Fstype != "btrfs" && partition.Fstype != "zfs" && partition.Fstype != "ext3" && partition.Fstype != "ext2" && partition.Fstype != "ntfs" && partition.Fstype != "fat32" && partition.Fstype != "exfat" {
			continue
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
func getHistoryDiskUsage(from string, to string) (string, error) {
	if from == "" && to == "" {
		file, err := os.ReadFile(diskMetricsFile)
		if err != nil {
			fmt.Println("Failed to read file:", err)
			return "", err
		}
		return string(file), nil
	}
	if from == "" {
		from = "1970-01-01T00:00:00Z"
	}
	if to == "" {
		to = time.Now().UTC().Format(time.RFC3339)
	}
	fromTime, err := time.Parse(time.RFC3339, from)
	if err != nil {
		fmt.Println("Failed to parse from time:", err)
		return "", err
	}
	toTime, err := time.Parse(time.RFC3339, to)
	if err != nil {
		fmt.Println("Failed to parse to time:", err)
		return "", err
	}

	fromTimeUnix := fromTime.UnixMilli()
	toTimeUnix := toTime.UnixMilli()
	file, err := os.ReadFile(diskMetricsFile)
	if err != nil {
		fmt.Println("Failed to read file:", err)
		return "", err
	}
	lines := string(file)
	var result string
	lines = lines[strings.Index(lines, "\n")+1:]
	for _, line := range strings.Split(lines, "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 4 {
			fmt.Println("Invalid line:", line)
			continue
		}
		time, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			fmt.Println("Failed to parse time:", err)
			continue
		}
		if time >= fromTimeUnix && time <= toTimeUnix {
			result += line + "\n"
		}
	}
	result = diskCsvHeader + result
	return result, nil

}
