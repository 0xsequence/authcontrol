//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=authcontrol.ridl -target=golang -pkg=proto -client -out=./authcontrol.gen.go
//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=authcontrol.ridl -target=typescript -client -out=./authcontrol.gen.ts
package proto

const SessionType_Max SessionType = SessionType_S2S + 1

// AndUp returns a list of all session types from the current one up to the maximum.
func (s SessionType) OrHigher() []SessionType {
	list := make([]SessionType, 0, SessionType_S2S-s+1)
	for i := s; i < SessionType_Max; i++ {
		list = append(list, i)
	}
	return list
}
