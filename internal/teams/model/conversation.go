package model

import "strings"

type ThreadProperties struct {
	OriginalThreadID  string `json:"originalThreadId"`
	ProductThreadType string `json:"productThreadType"`
	CreatedAt         string `json:"createdat"`
	IsCreator         bool   `json:"isCreator"`
	Topic             string `json:"topic"`
	ThreadTopic       string `json:"threadTopic"`
	Title             string `json:"title"`
	DisplayName       string `json:"displayName"`
	Name              string `json:"name"`
}

type ConversationMember struct {
	ID            string `json:"id"`
	MRI           string `json:"mri"`
	DisplayName   string `json:"displayName"`
	Name          string `json:"name"`
	IsSelf        bool   `json:"isSelf"`
	IsCurrentUser bool   `json:"isCurrentUser"`
}

type ConversationProperties struct {
	Topic       string `json:"topic"`
	ThreadTopic string `json:"threadTopic"`
	Title       string `json:"title"`
	DisplayName string `json:"displayName"`
	Name        string `json:"name"`
}

type RemoteConversation struct {
	ID               string                 `json:"id"`
	ThreadProperties ThreadProperties       `json:"threadProperties"`
	Topic            string                 `json:"topic"`
	Title            string                 `json:"title"`
	DisplayName      string                 `json:"displayName"`
	Name             string                 `json:"name"`
	Properties       ConversationProperties `json:"properties"`
	Members          []ConversationMember   `json:"members"`
	Participants     []ConversationMember   `json:"participants"`
	Consumers        []ConversationMember   `json:"consumers"`
}

const defaultRoomName = "Chat"

type Thread struct {
	ID             string
	ConversationID string
	Type           string
	CreatedAtRaw   string
	IsCreator      bool
	IsOneToOne     bool
	RoomName       string
}

func (c RemoteConversation) Normalize() (Thread, bool) {
	return c.NormalizeForSelf("")
}

func (c RemoteConversation) NormalizeForSelf(selfUserID string) (Thread, bool) {
	id := strings.TrimSpace(c.ThreadProperties.OriginalThreadID); if id == "" { id = strings.TrimSpace(c.ID) }
	if id == "" {
		return Thread{}, false
	}
	threadType := strings.TrimSpace(c.ThreadProperties.ProductThreadType)
	conversationID := strings.TrimSpace(c.ID)
	isOneToOne := threadType == "OneToOneChat" || c.isLikelyOneToOne(strings.TrimSpace(selfUserID))
	return Thread{
		ID:             id,
		ConversationID: conversationID,
		Type:           threadType,
		CreatedAtRaw:   c.ThreadProperties.CreatedAt,
		IsCreator:      c.ThreadProperties.IsCreator,
		IsOneToOne:     isOneToOne,
		RoomName:       c.resolveRoomName(isOneToOne, strings.TrimSpace(selfUserID)),
	}, true
}

func (c RemoteConversation) resolveRoomName(isOneToOne bool, selfUserID string) string {
	if isOneToOne {
		if dmName := c.resolveDMName(selfUserID); dmName != "" {
			return dmName
		}
		return ""
	}
	if name := c.resolveThreadName(); name != "" {
		return name
	}
	return defaultRoomName
}

func (c RemoteConversation) resolveDMName(selfUserID string) string {
	selfID := strings.TrimSpace(selfUserID)
	selfNorm := normalizeParticipantID(selfID)
	selfNames := c.collectSelfDisplayNames(selfID, selfNorm)
	fallback := ""
	for _, list := range [][]ConversationMember{c.Members, c.Participants, c.Consumers} {
		for _, member := range list {
			id := memberID(member)
			if isExplicitSelfMember(member, id, selfID, selfNorm) {
				continue
			}
			if isLikelyTeamsBotID(id) {
				continue
			}
			name := memberName(member)
			if name == "" {
				continue
			}
			if fallback == "" {
				fallback = name
			}
			if _, ok := selfNames[strings.ToLower(name)]; ok {
				continue
			}
			return name
		}
	}
	return fallback
}

func (c RemoteConversation) resolveThreadName() string {
	for _, candidate := range []string{
		c.ThreadProperties.Topic,
		c.ThreadProperties.ThreadTopic,
		c.ThreadProperties.Title,
		c.ThreadProperties.DisplayName,
		c.ThreadProperties.Name,
		c.Properties.Topic,
		c.Properties.ThreadTopic,
		c.Properties.Title,
		c.Properties.DisplayName,
		c.Properties.Name,
		c.Topic,
		c.Title,
		c.DisplayName,
		c.Name,
	} {
		if name := strings.TrimSpace(candidate); name != "" {
			return name
		}
	}
	return ""
}

func (c RemoteConversation) isLikelyOneToOne(selfUserID string) bool {
	if c.resolveThreadName() != "" {
		return false
	}
	selfID := strings.TrimSpace(selfUserID)
	selfNorm := normalizeParticipantID(selfID)
	selfNames := c.collectSelfDisplayNames(selfID, selfNorm)
	others := make(map[string]struct{})
	for _, list := range [][]ConversationMember{c.Members, c.Participants, c.Consumers} {
		for _, member := range list {
			rawID := memberID(member)
			if isExplicitSelfMember(member, rawID, selfID, selfNorm) {
				continue
			}
			if isLikelyTeamsBotID(rawID) {
				continue
			}
			if name := memberName(member); name != "" {
				if _, ok := selfNames[strings.ToLower(name)]; ok {
					continue
				}
			}
			idKey := normalizeParticipantID(rawID)
			if idKey == "" {
				idKey = strings.ToLower(memberName(member))
			}
			if idKey == "" {
				continue
			}
			others[idKey] = struct{}{}
			if len(others) > 1 {
				return false
			}
		}
	}
	return len(others) == 1
}

func (c RemoteConversation) collectSelfDisplayNames(selfUserID string, selfNorm string) map[string]struct{} {
	names := make(map[string]struct{})
	for _, list := range [][]ConversationMember{c.Members, c.Participants, c.Consumers} {
		for _, member := range list {
			id := memberID(member)
			if !isExplicitSelfMember(member, id, selfUserID, selfNorm) {
				continue
			}
			if name := memberName(member); name != "" {
				names[strings.ToLower(name)] = struct{}{}
			}
		}
	}
	return names
}

func memberID(member ConversationMember) string {
	if id := strings.TrimSpace(member.ID); id != "" {
		return id
	}
	return strings.TrimSpace(member.MRI)
}

func memberName(member ConversationMember) string {
	if name := strings.TrimSpace(member.DisplayName); name != "" {
		return name
	}
	return strings.TrimSpace(member.Name)
}

func isExplicitSelfMember(member ConversationMember, memberID string, selfUserID string, selfNorm string) bool {
	if member.IsSelf || member.IsCurrentUser {
		return true
	}
	if selfUserID != "" && memberID != "" && strings.EqualFold(memberID, selfUserID) {
		return true
	}
	if selfNorm != "" && normalizeParticipantID(memberID) == selfNorm {
		return true
	}
	return false
}

func normalizeParticipantID(raw string) string {
	id := strings.ToLower(strings.TrimSpace(raw))
	if id == "" {
		return ""
	}
	for {
		idx := strings.IndexByte(id, ':')
		if idx <= 0 || idx+1 >= len(id) {
			break
		}
		prefix := id[:idx]
		digitsOnly := true
		for _, ch := range prefix {
			if ch < '0' || ch > '9' {
				digitsOnly = false
				break
			}
		}
		if !digitsOnly {
			break
		}
		id = id[idx+1:]
	}
	return id
}

func isLikelyTeamsBotID(raw string) bool {
	id := strings.TrimSpace(strings.ToLower(raw))
	if id == "" {
		return false
	}
	return strings.HasPrefix(id, "28:") || strings.Contains(id, "teamsbot")
}
