package bit_l

// PlainVote defines the content of a plain vote.
type PlainVote struct {
	BlockHash   []byte
	BlockHeight uint64
	Opinion     bool // agree or disagree
	IsDBlock    bool // if the vote is for data block, IsDBlock == true
}

// VoteWithPartialSig encapsulates the PlainVote with the partial signature.
type VoteWithPartialSig struct {
	PlainVote
	Sender     string
	PartialSig []byte
}
