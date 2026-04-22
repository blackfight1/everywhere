package api

import (
	"hidden-attack-surface-scanner/internal/database"

	"gorm.io/gorm"
)

type PingbackEvidence struct {
	database.Pingback
	TriggerMethod         string `json:"trigger_method"`
	TriggerURL            string `json:"trigger_url"`
	TriggerRawRequest     string `json:"trigger_raw_request"`
	ReplayCommand         string `json:"replay_command"`
	TriggerResponseStatus *int   `json:"trigger_response_status"`
}

func (s *Server) buildPingbackEvidence(query *gorm.DB) ([]PingbackEvidence, error) {
	var pingbacks []database.Pingback
	if err := query.Find(&pingbacks).Error; err != nil {
		return nil, err
	}
	if len(pingbacks) == 0 {
		return []PingbackEvidence{}, nil
	}

	uniqueIDs := make([]string, 0, len(pingbacks))
	seen := make(map[string]struct{}, len(pingbacks))
	for _, row := range pingbacks {
		if row.UniqueID == "" {
			continue
		}
		if _, ok := seen[row.UniqueID]; ok {
			continue
		}
		seen[row.UniqueID] = struct{}{}
		uniqueIDs = append(uniqueIDs, row.UniqueID)
	}

	sentMap := make(map[string]database.SentPayload, len(uniqueIDs))
	if len(uniqueIDs) > 0 {
		var sentRows []database.SentPayload
		if err := s.db.Where("unique_id IN ?", uniqueIDs).Find(&sentRows).Error; err != nil {
			return nil, err
		}
		for _, row := range sentRows {
			sentMap[row.UniqueID] = row
		}
	}

	result := make([]PingbackEvidence, 0, len(pingbacks))
	for _, row := range pingbacks {
		item := PingbackEvidence{Pingback: row}
		if sent, ok := sentMap[row.UniqueID]; ok {
			item.TriggerMethod = sent.RequestMethod
			item.TriggerURL = sent.RequestURL
			item.TriggerRawRequest = sent.RawRequest
			item.ReplayCommand = sent.ReplayCommand
			item.TriggerResponseStatus = sent.ResponseStatus
		}
		result = append(result, item)
	}
	return result, nil
}
