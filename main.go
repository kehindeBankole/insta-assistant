package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

type Config struct {
	Port               string
	VerifyToken        string
	AppSecret          string
	IGUserID           string
	IGPageAccessToken  string
	OpenAIAPIKey       string
	OpenAIModel        string
	SystemPrompt       string
	MemoryTurns        int
	FollowupDelay      time.Duration
	FollowupMaxPerUser int
}

type Turn struct {
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

type ThreadState struct {
	SenderID       string    `json:"senderId"`
	Turns          []Turn    `json:"turns"`
	LastUserAt     time.Time `json:"lastUserAt"`
	LastBotAt      time.Time `json:"lastBotAt"`
	FollowupCount  int       `json:"followupCount"`
	NextFollowupAt time.Time `json:"nextFollowupAt"`
}

type App struct {
	cfg Config
	db  *bolt.DB
	mu  sync.Mutex
}

func main() {
	cfg := loadConfig()
	db, err := bolt.Open("insta-assistant.db", 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("threads"))
		return err
	}); err != nil {
		log.Fatal(err)
	}

	app := &App{cfg: cfg, db: db}
	go app.followupWorker()

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	http.HandleFunc("/ig-webhook", app.handleIGWebhook)

	log.Printf("insta-assistant listening on :%s", cfg.Port)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, nil))
}

func loadConfig() Config {
	memoryTurns := 12
	followupMax := 1
	if v := os.Getenv("MEMORY_TURNS"); v != "" {
		fmt.Sscanf(v, "%d", &memoryTurns)
	}
	if v := os.Getenv("FOLLOWUP_MAX_PER_USER"); v != "" {
		fmt.Sscanf(v, "%d", &followupMax)
	}
	followupDelay := 2 * time.Hour
	if v := os.Getenv("FOLLOWUP_DELAY"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			followupDelay = d
		}
	}
	model := os.Getenv("OPENAI_MODEL")
	if model == "" {
		model = "gpt-4o-mini"
	}
	prompt := os.Getenv("IG_BOT_SYSTEM_PROMPT")
	if prompt == "" {
		prompt = "You are an Instagram assistant. Be concise, friendly, and helpful. Keep replies under 3 short lines unless asked for more."
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	return Config{
		Port:               port,
		VerifyToken:        os.Getenv("IG_VERIFY_TOKEN"),
		AppSecret:          os.Getenv("IG_APP_SECRET"),
		IGUserID:           os.Getenv("IG_USER_ID"),
		IGPageAccessToken:  os.Getenv("IG_PAGE_ACCESS_TOKEN"),
		OpenAIAPIKey:       os.Getenv("OPENAI_API_KEY"),
		OpenAIModel:        model,
		SystemPrompt:       prompt,
		MemoryTurns:        memoryTurns,
		FollowupDelay:      followupDelay,
		FollowupMaxPerUser: followupMax,
	}
}

func (a *App) handleIGWebhook(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.handleVerify(w, r)
	case http.MethodPost:
		a.handleMessage(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleVerify(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("hub.mode")
	token := r.URL.Query().Get("hub.verify_token")
	challenge := r.URL.Query().Get("hub.challenge")
	if mode == "subscribe" && token == a.cfg.VerifyToken {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(challenge))
		return
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}

type incoming struct {
	Object string `json:"object"`
	Entry  []struct {
		Messaging []struct {
			Sender struct {
				ID string `json:"id"`
			} `json:"sender"`
			Message struct {
				Text   string `json:"text"`
				IsEcho bool   `json:"is_echo"`
			} `json:"message"`
		} `json:"messaging"`
	} `json:"entry"`
}

func (a *App) handleMessage(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if a.cfg.AppSecret != "" && !verifyMetaSignature(a.cfg.AppSecret, body, r.Header.Get("X-Hub-Signature-256")) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	var in incoming
	if err := json.Unmarshal(body, &in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	for _, e := range in.Entry {
		for _, m := range e.Messaging {
			sender := m.Sender.ID
			text := strings.TrimSpace(m.Message.Text)
			if sender == "" || text == "" || m.Message.IsEcho {
				continue
			}
			go a.processIncoming(sender, text)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func verifyMetaSignature(appSecret string, body []byte, sigHeader string) bool {
	if appSecret == "" || sigHeader == "" {
		return false
	}
	parts := strings.SplitN(sigHeader, "=", 2)
	if len(parts) != 2 || parts[0] != "sha256" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(appSecret))
	mac.Write(body)
	expected := mac.Sum(nil)
	got, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	return hmac.Equal(expected, got)
}

func (a *App) processIncoming(senderID, userText string) {
	st, _ := a.getThread(senderID)
	now := time.Now().UTC()
	st.SenderID = senderID
	st.LastUserAt = now
	st.Turns = append(st.Turns, Turn{Role: "user", Content: userText, Timestamp: now})
	st.Turns = trimTurns(st.Turns, a.cfg.MemoryTurns)

	reply, err := a.generateReply(st.Turns)
	if err != nil {
		log.Printf("generateReply error: %v", err)
		return
	}
	if err := a.sendIGMessage(senderID, reply); err != nil {
		log.Printf("sendIGMessage error: %v", err)
		return
	}
	st.LastBotAt = time.Now().UTC()
	st.NextFollowupAt = st.LastBotAt.Add(a.cfg.FollowupDelay)
	st.FollowupCount = 0
	st.Turns = append(st.Turns, Turn{Role: "assistant", Content: reply, Timestamp: st.LastBotAt})
	st.Turns = trimTurns(st.Turns, a.cfg.MemoryTurns)
	_ = a.saveThread(st)
	log.Printf("replied sender=%s", senderID)
}

func trimTurns(turns []Turn, n int) []Turn {
	if n <= 0 || len(turns) <= n {
		return turns
	}
	return turns[len(turns)-n:]
}

func (a *App) generateReply(turns []Turn) (string, error) {
	if a.cfg.OpenAIAPIKey == "" {
		return "", errors.New("OPENAI_API_KEY missing")
	}
	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	messages := []msg{{Role: "system", Content: a.cfg.SystemPrompt}}
	for _, t := range turns {
		messages = append(messages, msg{Role: t.Role, Content: t.Content})
	}

	payload := map[string]any{
		"model":       a.cfg.OpenAIModel,
		"messages":    messages,
		"temperature": 0.6,
		"max_tokens":  220,
	}
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+a.cfg.OpenAIAPIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		bb, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("openai status=%d body=%s", resp.StatusCode, string(bb))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", errors.New("no choices")
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), nil
}

func (a *App) sendIGMessage(recipientID, text string) error {
	if a.cfg.IGUserID == "" || a.cfg.IGPageAccessToken == "" {
		return errors.New("IG_USER_ID or IG_PAGE_ACCESS_TOKEN missing")
	}
	url := fmt.Sprintf("https://graph.facebook.com/v23.0/%s/messages?access_token=%s", a.cfg.IGUserID, a.cfg.IGPageAccessToken)
	payload := map[string]any{
		"messaging_product": "instagram",
		"recipient":         map[string]any{"id": recipientID},
		"message":           map[string]any{"text": text},
	}
	b, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		bb, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("graph status=%d body=%s", resp.StatusCode, string(bb))
	}
	return nil
}

func (a *App) followupWorker() {
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for range t.C {
		threads, err := a.listThreads()
		if err != nil {
			continue
		}
		sort.Slice(threads, func(i, j int) bool { return threads[i].NextFollowupAt.Before(threads[j].NextFollowupAt) })
		now := time.Now().UTC()
		for _, st := range threads {
			if st.SenderID == "" || st.NextFollowupAt.IsZero() || st.NextFollowupAt.After(now) {
				continue
			}
			if st.FollowupCount >= a.cfg.FollowupMaxPerUser {
				continue
			}
			if st.LastUserAt.After(st.LastBotAt) { // user already replied
				continue
			}
			msg := "Hey — just checking in. Want me to help with anything else?"
			if err := a.sendIGMessage(st.SenderID, msg); err != nil {
				log.Printf("followup send error: %v", err)
				continue
			}
			st.FollowupCount++
			st.LastBotAt = now
			st.NextFollowupAt = now.Add(a.cfg.FollowupDelay)
			st.Turns = append(st.Turns, Turn{Role: "assistant", Content: msg, Timestamp: now})
			st.Turns = trimTurns(st.Turns, a.cfg.MemoryTurns)
			_ = a.saveThread(st)
			log.Printf("followup sent sender=%s", st.SenderID)
		}
	}
}

func (a *App) getThread(senderID string) (ThreadState, error) {
	st := ThreadState{SenderID: senderID}
	err := a.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("threads"))
		v := b.Get([]byte(senderID))
		if v == nil {
			return nil
		}
		return json.Unmarshal(v, &st)
	})
	return st, err
}

func (a *App) saveThread(st ThreadState) error {
	b, _ := json.Marshal(st)
	return a.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("threads")).Put([]byte(st.SenderID), b)
	})
}

func (a *App) listThreads() ([]ThreadState, error) {
	out := []ThreadState{}
	err := a.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("threads")).ForEach(func(k, v []byte) error {
			var st ThreadState
			if err := json.Unmarshal(v, &st); err == nil {
				out = append(out, st)
			}
			return nil
		})
	})
	return out, err
}
