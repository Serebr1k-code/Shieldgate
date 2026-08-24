// Package api exposes the REST + WebSocket interface for the web UI.
package api

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Event is the WS broadcast envelope (mirrors state.Event plus extras).
type Event struct {
	Type      string          `json:"type"`
	ServiceID string          `json:"service_id,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	Message   string          `json:"message,omitempty"`
	At        time.Time       `json:"at"`
}

// Hub maintains connected WebSocket clients and broadcasts events.
type Hub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]struct{}

	upgrader websocket.Upgrader
}

func NewHub() *Hub {
	return &Hub{
		clients: make(map[*websocket.Conn]struct{}),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(r *http.Request) bool { return true }, // LAN UI
		},
	}
}

// Add registers a client (after upgrade).
func (h *Hub) Add(c *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[c] = struct{}{}
}

func (h *Hub) remove(c *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, c)
}

func (h *Hub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Broadcast sends an event to all clients; slow/dead clients are dropped.
func (h *Hub) Broadcast(ev Event) {
	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := c.WriteMessage(websocket.TextMessage, data); err != nil {
			go func(dead *websocket.Conn) {
				h.remove(dead)
				dead.Close()
			}(c)
		}
	}
}

// ServeWS upgrades an HTTP request to a WebSocket and keeps it open.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	c, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	h.Add(c)
	defer func() {
		h.remove(c)
		c.Close()
	}()
	// Reader loop: discard client messages; exit on close.
	for {
		if _, _, err := c.ReadMessage(); err != nil {
			return
		}
	}
}
