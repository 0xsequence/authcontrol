package authcontrol

import (
	"github.com/go-chi/metrics"
)

var (
	// Prometheus metrics.
	requestsCounter        = metrics.CounterWith[sessionLabels]("authcontrol_requests_total", "Total number of requests by session type.")
	requestsServiceCounter = metrics.CounterWith[serviceLabels]("authcontrol_requests_service_total", "Total number of requests by S2S service.")
	requestsProjectCounter = metrics.CounterWith[projectLabels]("authcontrol_requests_project_total", "Total number of requests by project ID.")
)

type sessionLabels struct {
	SessionType string `label:"session_type"`
	RateLimited string `label:"rate_limited"`
}

type serviceLabels struct {
	Service string `label:"service"`
}

type projectLabels struct {
	ProjectID string `label:"project_id"`
	Status    string `label:"status"`
}
