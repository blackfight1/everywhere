package database

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ScanTask struct {
	ID                string    `json:"id" gorm:"primaryKey;size:36"`
	Status            string    `json:"status" gorm:"index"`
	Mode              string    `json:"mode"`
	TargetSetID       string    `json:"target_set_id" gorm:"index"`
	TargetSetName     string    `json:"target_set_name"`
	Config            string    `json:"config" gorm:"type:text"`
	TargetCount       int       `json:"target_count"`
	EstimatedRequests int       `json:"estimated_requests"`
	RequestSent       int       `json:"request_sent"`
	PingbackCount     int       `json:"pingback_count"`
	ResponseHitCount  int       `json:"response_hit_count"`
	BatchSize         int       `json:"batch_size"`
	BatchCount        int       `json:"batch_count"`
	CurrentBatch      int       `json:"current_batch"`
	CompletedTargets  int       `json:"completed_targets"`
	CurrentTarget     string    `json:"current_target" gorm:"type:text"`
	CurrentStage      string    `json:"current_stage"`
	CreatedAt         time.Time `json:"created_at"`
	StartedAt         time.Time `json:"started_at"`
	CompletedAt       time.Time `json:"completed_at"`
	LastError         string    `json:"last_error" gorm:"type:text"`
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

type ResponseFinding struct {
	ID                  string    `json:"id" gorm:"primaryKey;size:36"`
	ScanTaskID          string    `json:"scan_task_id" gorm:"index"`
	TargetURL           string    `json:"target_url" gorm:"index"`
	PayloadType         string    `json:"payload_type" gorm:"index"`
	PayloadKey          string    `json:"payload_key" gorm:"index"`
	VariantKey          string    `json:"variant_key" gorm:"index"`
	RequestMethod       string    `json:"request_method"`
	RequestURL          string    `json:"request_url" gorm:"type:text"`
	RawRequest          string    `json:"raw_request" gorm:"type:text"`
	ReplayCommand       string    `json:"replay_command" gorm:"type:text"`
	ResponseStatus      *int      `json:"response_status"`
	ResponseHeaders     string    `json:"response_headers" gorm:"type:text"`
	ResponseBodyExcerpt string    `json:"response_body_excerpt" gorm:"type:text"`
	MatcherName         string    `json:"matcher_name"`
	Severity            string    `json:"severity" gorm:"index"`
	Confidence          string    `json:"confidence" gorm:"index"`
	Upstream            string    `json:"upstream"`
	CreatedAt           time.Time `json:"created_at" gorm:"index"`
}

func (r *ResponseFinding) BeforeCreate(_ *gorm.DB) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	return nil
}

type NotificationState struct {
	FindingKey        string    `json:"finding_key" gorm:"primaryKey;type:text"`
	ScanTaskID        string    `json:"scan_task_id" gorm:"index"`
	TargetURL         string    `json:"target_url" gorm:"type:text"`
	PayloadType       string    `json:"payload_type"`
	PayloadKey        string    `json:"payload_key" gorm:"index"`
	Confidence        string    `json:"confidence" gorm:"index"`
	Evidence          string    `json:"evidence"`
	LastProtocol      string    `json:"last_protocol"`
	LastRemoteAddress string    `json:"last_remote_address"`
	NotificationKind  string    `json:"notification_kind"`
	LastNotifiedAt    time.Time `json:"last_notified_at" gorm:"index"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type TargetSet struct {
	ID           string    `json:"id" gorm:"primaryKey;size:36"`
	Name         string    `json:"name" gorm:"index"`
	SourceType   string    `json:"source_type" gorm:"index"`
	Status       string    `json:"status" gorm:"index"`
	RawCount     int       `json:"raw_count"`
	ValidCount   int       `json:"valid_count"`
	DedupedCount int       `json:"deduped_count"`
	InvalidCount int       `json:"invalid_count"`
	LastError    string    `json:"last_error" gorm:"type:text"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (t *TargetSet) BeforeCreate(_ *gorm.DB) error {
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	return nil
}

type TargetRecord struct {
	ID          string    `json:"id" gorm:"primaryKey;size:36"`
	TargetSetID string    `json:"target_set_id" gorm:"index;uniqueIndex:idx_target_set_url,priority:1"`
	URL         string    `json:"url" gorm:"type:text;uniqueIndex:idx_target_set_url,priority:2"`
	Scheme      string    `json:"scheme" gorm:"index"`
	Host        string    `json:"host" gorm:"index"`
	Port        int       `json:"port"`
	Path        string    `json:"path" gorm:"type:text"`
	Position    int       `json:"position" gorm:"index"`
	CreatedAt   time.Time `json:"created_at"`
}

func (t *TargetRecord) BeforeCreate(_ *gorm.DB) error {
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	return nil
}

type TargetImportJob struct {
	ID             string    `json:"id" gorm:"primaryKey;size:36"`
	TargetSetID    string    `json:"target_set_id" gorm:"index"`
	Filename       string    `json:"filename"`
	Status         string    `json:"status" gorm:"index"`
	TotalLines     int       `json:"total_lines"`
	ProcessedLines int       `json:"processed_lines"`
	ValidCount     int       `json:"valid_count"`
	DedupedCount   int       `json:"deduped_count"`
	InvalidCount   int       `json:"invalid_count"`
	LastError      string    `json:"last_error" gorm:"type:text"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	CompletedAt    time.Time `json:"completed_at"`
}

func (t *TargetImportJob) BeforeCreate(_ *gorm.DB) error {
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	return nil
}
