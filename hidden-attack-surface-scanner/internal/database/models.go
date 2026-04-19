package database

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ScanTask struct {
	ID            string    `json:"id" gorm:"primaryKey;size:36"`
	Status        string    `json:"status" gorm:"index"`
	Mode          string    `json:"mode"`
	Config        string    `json:"config" gorm:"type:text"`
	TargetCount   int       `json:"target_count"`
	RequestSent   int       `json:"request_sent"`
	PingbackCount int       `json:"pingback_count"`
	CreatedAt     time.Time `json:"created_at"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	LastError     string    `json:"last_error" gorm:"type:text"`
}

func (s *ScanTask) BeforeCreate(_ *gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.NewString()
	}
	return nil
}

type PayloadTemplate struct {
	ID        string    `json:"id" gorm:"primaryKey;size:36"`
	Active    bool      `json:"active"`
	Type      string    `json:"type" gorm:"index"`
	Key       string    `json:"key" gorm:"index"`
	Value     string    `json:"value" gorm:"type:text"`
	Group     string    `json:"group" gorm:"index"`
	Comment   string    `json:"comment" gorm:"type:text"`
	Position  int       `json:"position" gorm:"index"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (p *PayloadTemplate) BeforeCreate(_ *gorm.DB) error {
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	return nil
}

type SentPayload struct {
	UniqueID       string    `json:"unique_id" gorm:"primaryKey"`
	ScanTaskID     string    `json:"scan_task_id" gorm:"index"`
	TargetURL      string    `json:"target_url"`
	PayloadType    string    `json:"payload_type"`
	PayloadKey     string    `json:"payload_key"`
	PayloadValue   string    `json:"payload_value" gorm:"type:text"`
	ResponseStatus *int      `json:"response_status"`
	SentAt         time.Time `json:"sent_at" gorm:"index"`
}

type Pingback struct {
	ID               string    `json:"id" gorm:"primaryKey;size:36"`
	UniqueID         string    `json:"unique_id" gorm:"uniqueIndex"`
	ScanTaskID       string    `json:"scan_task_id" gorm:"index"`
	TargetURL        string    `json:"target_url"`
	PayloadType      string    `json:"payload_type"`
	PayloadKey       string    `json:"payload_key"`
	PayloadValue     string    `json:"payload_value" gorm:"type:text"`
	CallbackProtocol string    `json:"callback_protocol" gorm:"index"`
	RemoteAddress    string    `json:"remote_address"`
	ReverseDNS       string    `json:"reverse_dns"`
	AsnInfo          string    `json:"asn_info" gorm:"type:text"`
	RawRequest       string    `json:"raw_request" gorm:"type:text"`
	SentAt           time.Time `json:"sent_at"`
	ReceivedAt       time.Time `json:"received_at" gorm:"index"`
	DelaySeconds     float64   `json:"delay_seconds"`
	Severity         string    `json:"severity" gorm:"index"`
	FromOwnIP        bool      `json:"from_own_ip"`
}

func (p *Pingback) BeforeCreate(_ *gorm.DB) error {
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	return nil
}
