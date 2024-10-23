//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=authcontrol.ridl -target=golang@v0.16.0 -pkg=proto -client -out=./authcontrol.gen.go
//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=authcontrol.ridl -target=typescript@v0.15.0 -client -out=./authcontrol.gen.ts
package proto

const SessionType_Max SessionType = SessionType_Service + 1

// AndUp returns a list of all session types from the current one up to the maximum.
func (s SessionType) OrHigher() []SessionType {
	list := make([]SessionType, 0, SessionType_Service-s+1)
	for i := s; i < SessionType_Max; i++ {
		list = append(list, i)
	}
	return list
}
