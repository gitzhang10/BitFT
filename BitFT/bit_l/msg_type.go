package bit_l

// Message tags to indicate the type of a message.
const (
	ProposalTag uint8 = iota
	VoteTag
	SortitionTag
	RBCValTag
	RBCEchoTag
	RBCReadyTag

)

var rbcMsgType = map[string]uint8{
	"VAL":   RBCValTag,
	"ECHO":  RBCEchoTag,
	"READY": RBCReadyTag,

}

