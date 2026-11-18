package roledfiber

import (
	"errors"

	"github.com/gofiber/fiber/v3"
	fibersession "github.com/gofiber/fiber/v3/middleware/session"
)

// fiberSession adapts the Fiber v3 session middleware to the web.Session
// interface. Sessions are persisted automatically by the session middleware
// after the handler returns, so Save is a no-op.
type fiberSession struct {
	m *fibersession.Middleware
}

func (s *fiberSession) Get(key string) (string, bool) {
	value, ok := s.m.Get(key).(string)
	return value, ok
}

func (s *fiberSession) Set(key string, value string) {
	s.m.Set(key, value)
}

func (s *fiberSession) Delete(key string) {
	s.m.Delete(key)
}

func (s *fiberSession) Save() error {
	return nil
}

// session returns the request's session wrapped as a web.Session. It requires
// the Fiber session middleware (session.New()) to be registered before these
// routes.
func (h *Handler) session(c fiber.Ctx) (*fiberSession, error) {
	m := fibersession.FromContext(c)
	if m == nil {
		return nil, errors.New("roled: fiber session middleware is not registered")
	}
	return &fiberSession{m: m}, nil
}
