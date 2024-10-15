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
		ticker := time.NewTicker(time.Duration(refreshRateSeconds) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("Recovered from panic in collector: %v", r)
						}
					}()

					queryTimeInUnixString := getUnixTimeInMilliUTC()

					// CPU usage
					overallPercentage, err := cpu.Percent(0, false)
					if err != nil {
						log.Printf("Error getting CPU percentage: %v", err)
						return
					}

					_, err = db.Exec(`INSERT INTO cpu_usage (time, percent) VALUES (?, ?)`, queryTimeInUnixString, fmt.Sprintf("%.2f", overallPercentage[0]))
					if err != nil {
						log.Printf("Error inserting CPU usage into database: %v", err)
					}

					// Memory usage
					memory, err := mem.VirtualMemory()
					if err != nil {
						log.Printf("Error getting memory usage: %v", err)
						return
					}

					_, err = db.Exec(`INSERT INTO memory_usage (time, total, available, used, usedPercent, free) VALUES (?, ?, ?, ?, ?, ?)`,
						queryTimeInUnixString, memory.Total, memory.Available, memory.Used, math.Round(memory.UsedPercent*100)/100, memory.Free)
					if err != nil {
						log.Printf("Error inserting memory usage into database: %v", err)
					}

					// Cleanup old data
					totalRowsToKeep := 10
					currentTime := time.Now().UTC().UnixMilli()
					cutoffTime := currentTime - int64(collectorRetentionPeriodDays*24*60*60*1000)

					cleanupTable := func(tableName string) {
						var totalRows int
						err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)).Scan(&totalRows)
						if err != nil {
							log.Printf("Error counting rows in %s: %v", tableName, err)
							return
						}

						if totalRows > totalRowsToKeep {
							_, err = db.Exec(fmt.Sprintf(`DELETE FROM %s WHERE CAST(time AS BIGINT) < ? AND time NOT IN (SELECT time FROM %s ORDER BY time DESC LIMIT ?)`, tableName, tableName),
								cutoffTime, totalRowsToKeep)
							if err != nil {
								log.Printf("Error deleting old data from %s: %v", tableName, err)
							}
						}
					}

					cleanupTable("cpu_usage")
					cleanupTable("memory_usage")
				}()
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
