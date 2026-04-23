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
	RequestMethod  string    `json:"request_method"`
	RequestURL     string    `json:"request_url" gorm:"type:text"`
	RawRequest     string    `json:"raw_request" gorm:"type:text"`
	ReplayCommand  string    `json:"replay_command" gorm:"type:text"`
	ResponseStatus *int      `json:"response_status"`
	SentAt         time.Time `json:"sent_at" gorm:"index"`
}

type Pingback struct {
	ID               string    `json:"id" gorm:"primaryKey;size:36"`
	UniqueID         string    `json:"unique_id" gorm:"index;uniqueIndex:idx_pingbacks_uid_proto,priority:1"`
	ScanTaskID       string    `json:"scan_task_id" gorm:"index"`
	TargetURL        string    `json:"target_url"`
	PayloadType      string    `json:"payload_type"`
	PayloadKey       string    `json:"payload_key"`
	PayloadValue     string    `json:"payload_value" gorm:"type:text"`
	CallbackProtocol string    `json:"callback_protocol" gorm:"index;uniqueIndex:idx_pingbacks_uid_proto,priority:2"`
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

type NotificationState struct {
	FindingKey         string    `json:"finding_key" gorm:"primaryKey;type:text"`
	ScanTaskID         string    `json:"scan_task_id" gorm:"index"`
	TargetURL          string    `json:"target_url" gorm:"type:text"`
	PayloadType        string    `json:"payload_type"`
	PayloadKey         string    `json:"payload_key" gorm:"index"`
	Confidence         string    `json:"confidence" gorm:"index"`
	Evidence           string    `json:"evidence"`
	LastProtocol       string    `json:"last_protocol"`
	LastRemoteAddress  string    `json:"last_remote_address"`
	NotificationKind   string    `json:"notification_kind"`
	LastNotifiedAt     time.Time `json:"last_notified_at" gorm:"index"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}
