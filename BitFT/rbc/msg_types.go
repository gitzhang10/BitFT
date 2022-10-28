package rbc

type VALMsg struct {
	Rbcname      string
	Proposer     string
	DataSN       uint64
	DataLen      uint64
	RootHash     []byte
	MerkleBranch [][]byte
	ShardData    []byte
}



type ECHOMsg struct {
	Rbcname      string
	Sender       string
	Proposer     string
	DataSN       uint64
	DataLen      uint64
	RootHash     []byte
	MerkleBranch [][]byte
	ShardData    []byte
}


type READYMsg struct {
	Rbcname  string
	Sender   string
	Proposer string
	DataSN   uint64
	RootHash []byte
}


