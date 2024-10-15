package main

import (
	"fmt"
	"log"
	"math"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
)

func collector() {
	fmt.Printf("[%s] Starting metrics recorder with refresh rate of %d seconds and retention period of %d days.\n", time.Now().Format("2006-01-02 15:04:05"), refreshRateSeconds, collectorRetentionPeriodDays)

	go func() {
		for {
			time.Sleep(time.Duration(refreshRateSeconds) * time.Second)
			// fmt.Printf("[%s] Recording metrics data.\n", time.Now().Format("2006-01-02 15:04:05"))

			queryTimeInUnixString := getUnixTimeInMilliUTC()
			overallPercentage, err := cpu.Percent(0, false)
			if err != nil {
				log.Printf("Error getting CPU percentage: %v", err)
				continue
			}

			_, err = db.Exec(`INSERT INTO cpu_usage (time, percent) VALUES (?, ?)`, queryTimeInUnixString, fmt.Sprintf("%.2f", overallPercentage[0]))
			if err != nil {
				log.Printf("Error inserting into database: %v", err)
			}

			memory, err := mem.VirtualMemory()
			if err != nil {
				log.Printf("Error getting memory usage: %v", err)
				continue
			}

			_, err = db.Exec(`INSERT INTO memory_usage (time, total, available, used, usedPercent, free) VALUES (?, ?, ?, ?, ?, ?)`, queryTimeInUnixString, memory.Total, memory.Available, memory.Used, math.Round(memory.UsedPercent*100)/100, memory.Free)
			if err != nil {
				log.Printf("Error inserting into database: %v", err)
			}

			totalRowsToKeep := 10
			currentTime := time.Now().UTC().UnixMilli()
			cutoffTime := currentTime - int64(collectorRetentionPeriodDays*24*60*60*1000)

			// Count the total number of rows
			var totalRows int
			err = db.QueryRow("SELECT COUNT(*) FROM cpu_usage").Scan(&totalRows)
			if err != nil {
				log.Printf("Error counting rows: %v", err)
				continue
			}

			if totalRows > totalRowsToKeep {
				// Delete old data while keeping at least 10 rows
				_, err = db.Exec(`DELETE FROM cpu_usage WHERE CAST(time AS BIGINT) < ? AND time NOT IN (SELECT time FROM cpu_usage ORDER BY time DESC LIMIT ?)`, cutoffTime, totalRowsToKeep)
				if err != nil {
					log.Printf("Error deleting old data: %v", err)
				}
			}

			err = db.QueryRow("SELECT COUNT(*) FROM memory_usage").Scan(&totalRows)
			if err != nil {
				log.Printf("Error counting rows: %v", err)
				continue
			}

			if totalRows > totalRowsToKeep {
				// Delete old data while keeping at least 10 rows
				_, err = db.Exec(`DELETE FROM memory_usage WHERE CAST(time AS BIGINT) < ? AND time NOT IN (SELECT time FROM memory_usage ORDER BY time DESC LIMIT ?)`, cutoffTime, totalRowsToKeep)
				if err != nil {
					log.Printf("Error deleting old data: %v", err)
				}
			}
		}
	}()
}

func cleanup() {
	fmt.Printf("[%s] Removing old data.\n", time.Now().Format("2006-01-02 15:04:05"))

	cutoffTime := time.Now().AddDate(0, 0, -collectorRetentionPeriodDays).UnixMilli()

	fmt.Println(cutoffTime)
	_, err := db.Exec(`DELETE FROM cpu_usage WHERE CAST(time AS BIGINT) < ?`, cutoffTime)
	if err != nil {
		log.Printf("Error removing old data: %v", err)
	}

	_, err = db.Exec(`DELETE FROM memory_usage WHERE CAST(time AS BIGINT) < ?`, cutoffTime)
	if err != nil {
		log.Printf("Error removing old memory data: %v", err)
	}

	go func() {
		for {
			time.Sleep(24 * time.Hour)
			cleanup()
		}
	}()
}
