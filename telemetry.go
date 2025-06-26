package authcontrol

import (
	"github.com/go-chi/metrics"
)

var (
	sessionTypeCounter = metrics.CounterWith[sessionLabels]("authcontrol_requests_total", "Total number of requests by session type.")
	projectCounter     = metrics.CounterWith[projectLabels]("authcontrol_project_requests_total", "Total number of requests by project ID.")
)

type sessionLabels struct {
	SessionType string `label:"session_type"`
	Status      string `label:"status"`
}

type projectLabels struct {
	ProjectID string `label:"project_id"`
	Status    string `label:"status"`
}
