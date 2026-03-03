//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=authcontrol.ridl -target=golang -pkg=proto -client -out=./authcontrol.gen.go
//go:generate go run github.com/webrpc/webrpc/cmd/webrpc-gen -schema=authcontrol.ridl -target=typescript -client -out=./authcontrol.gen.ts
package proto

const SessionType_Max SessionType = SessionType_S2S + 1

// AndUp returns a list of all session types from the current one up to the maximum.
func (s SessionType) OrHigher() SessionTypes {
	list := make([]SessionType, 0, SessionType_S2S-s+1)
	for i := s; i < SessionType_Max; i++ {
		list = append(list, i)
	}
	return NewSessionTypes(list...)
}

// SessionTypes is a list of session types, encoded as a bitfield.
// SessionType(n) is represented by n=-the bit.
type SessionTypes uint64

// NewSessionTypes returns a new SessionTypes with the given session types.
func NewSessionTypes(sessions ...SessionType) SessionTypes {
	var acl SessionTypes
	for _, v := range sessions {
		acl = acl.And(v)
	}
	return acl
}

// And returns a new SessionTypes with the given session types added.
func (a SessionTypes) And(session ...SessionType) SessionTypes {
	for _, v := range session {
		a |= 1 << v
	}
	return a
}

// Includes returns true if the SessionTypes includes the given session type.
func (t SessionTypes) Includes(session SessionType) bool {
	return t&SessionTypes(1<<session) != 0
}
