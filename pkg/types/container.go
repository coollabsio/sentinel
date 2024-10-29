package types

/* Package contains types shared between collector and pusher */

type ContainerMetrics struct {
	Name                  string  `json:"name"`
	Time                  string  `json:"time"`
	CPUUsagePercentage    float64 `json:"cpu_usage_percentage"`
	MemoryUsagePercentage float64 `json:"memory_usage_percentage"`
	MemoryUsed            uint64  `json:"memory_used"`
	MemoryAvailable       uint64  `json:"available_memory"`
}

type Container struct {
	Time         string            `json:"time"`
	ID           string            `json:"id"`
	Image        string            `json:"image"`
	Name         string            `json:"name"`
	State        string            `json:"state"`
	Labels       map[string]string `json:"labels"`
	HealthStatus string            `json:"health_status"`
}
