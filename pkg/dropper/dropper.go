package dropper

type Dropper interface {
	GetName() string
	SetFileName(fileName string)
	GetPayloadUrl() string
	SetPayloadUrl(payloadUrl string)
	SetOutFile(outFile string)
	GetResult() string
	PrintResult() string
	Render() error
}
