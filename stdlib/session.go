package stdlib

import (
	"encoding/json"

	"github.com/gorilla/sessions"
	"github.com/roledio/roled-go"
)

const authSessionKey = "roled_auth_session"

func loadAuthSession(sess *sessions.Session) (*roled.AuthSession, error) {
	raw, _ := sess.Values[authSessionKey].(string)
	if raw == "" {
		return &roled.AuthSession{}, nil
	}

	var authSess roled.AuthSession
	if err := json.Unmarshal([]byte(raw), &authSess); err != nil {
		return nil, err
	}
	return &authSess, nil
}

// setAuthSession marshals authSess into the session's Values. It does not
// persist anything; call sess.Save(r, w) afterwards to write the session.
func setAuthSession(sess *sessions.Session, authSess *roled.AuthSession) error {
	raw, err := json.Marshal(authSess)
	if err != nil {
		return err
	}
	sess.Values[authSessionKey] = string(raw)
	return nil
}

func clearAuthSession(sess *sessions.Session) {
	delete(sess.Values, authSessionKey)
}
