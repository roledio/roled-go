package web

import (
	"reflect"
	"testing"
	"time"

	"github.com/roledio/roled-go"
)

func TestLoadAuthSessionMissingKey(t *testing.T) {
	sess := newMemSession()

	authSess, err := LoadAuthSession(sess)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authSess == nil {
		t.Fatal("expected non-nil AuthSession")
	}
	if authSess.IsAuthenticated() {
		t.Fatal("expected empty session to be unauthenticated")
	}
}

func TestLoadAuthSessionEmptyValue(t *testing.T) {
	sess := newMemSession()
	sess.Set(authSessionKey, "")

	authSess, err := LoadAuthSession(sess)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authSess.IsAuthenticated() {
		t.Fatal("expected empty payload to be unauthenticated")
	}
}

func TestSetAndLoadAuthSessionRoundTrip(t *testing.T) {
	sess := newMemSession()
	now := time.Now().UTC().Truncate(time.Millisecond)
	want := &roled.AuthSession{
		ID:                    "sess_1",
		OAuthState:            "state_abc",
		PKCEVerifier:          "verifier_xyz",
		AccessToken:           "at_123",
		AccessTokenExpiresAt:  now.Add(time.Hour),
		RefreshToken:          "rt_456",
		RefreshTokenExpiresAt: now.Add(24 * time.Hour),
		CreatedAt:             now,
		UpdatedAt:             now.Add(time.Minute),
	}

	if err := SetAuthSession(sess, want); err != nil {
		t.Fatalf("SetAuthSession failed: %v", err)
	}

	got, err := LoadAuthSession(sess)
	if err != nil {
		t.Fatalf("LoadAuthSession failed: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\n got: %+v\nwant: %+v", got, want)
	}
	if !got.IsAuthenticated() {
		t.Fatal("expected round-tripped session to be authenticated")
	}
}

func TestSetAuthSessionDoesNotSave(t *testing.T) {
	sess := newMemSession()

	if err := SetAuthSession(sess, &roled.AuthSession{RefreshToken: "rt"}); err != nil {
		t.Fatal(err)
	}
	if sess.saveCount() != 0 {
		t.Fatalf("SetAuthSession must not persist; Save() called %d times", sess.saveCount())
	}
}

func TestSetAuthSessionOverwrites(t *testing.T) {
	sess := newMemSession()

	if err := SetAuthSession(sess, &roled.AuthSession{AccessToken: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := SetAuthSession(sess, &roled.AuthSession{AccessToken: "second"}); err != nil {
		t.Fatal(err)
	}

	got, err := LoadAuthSession(sess)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "second" {
		t.Fatalf("expected overwrite, got %q", got.AccessToken)
	}
}

func TestLoadAuthSessionCorruptJSON(t *testing.T) {
	sess := newMemSession()
	sess.Set(authSessionKey, "{not-json")

	if _, err := LoadAuthSession(sess); err == nil {
		t.Fatal("expected error for corrupt session payload")
	}
}

func TestLoadAuthSessionTypeMismatch(t *testing.T) {
	sess := newMemSession()
	// Valid JSON but wrong field types must fail unmarshalling.
	sess.Set(authSessionKey, `{"AccessToken":123,"RefreshToken":true}`)

	if _, err := LoadAuthSession(sess); err == nil {
		t.Fatal("expected error for type-mismatched payload")
	}
}

func TestClearAuthSession(t *testing.T) {
	sess := newMemSession()
	if err := SetAuthSession(sess, &roled.AuthSession{RefreshToken: "rt"}); err != nil {
		t.Fatal(err)
	}

	ClearAuthSession(sess)

	if sess.hasKey(authSessionKey) {
		t.Fatal("expected session key to be deleted")
	}

	// Clearing an already-empty session must be a no-op.
	ClearAuthSession(sess)
}
