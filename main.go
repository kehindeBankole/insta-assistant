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
	IGPageID           string
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
	http.HandleFunc("/privacy", app.handlePrivacy)
	http.HandleFunc("/data-deletion", app.handleDataDeletion)
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
		IGPageID:           os.Getenv("IG_PAGE_ID"),
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
	log.Printf("webhook hit method=%s path=%s ua=%q remote=%s", r.Method, r.URL.Path, r.UserAgent(), r.RemoteAddr)
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
	log.Printf("verify attempt mode=%q token_match=%t challenge_len=%d", mode, token == a.cfg.VerifyToken, len(challenge))
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
		Changes []struct {
			Field string `json:"field"`
			Value struct {
				Sender struct {
					ID string `json:"id"`
				} `json:"sender"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"value"`
		} `json:"changes"`
	} `json:"entry"`
}

func (a *App) handleMessage(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	sig := r.Header.Get("X-Hub-Signature-256")
	if a.cfg.AppSecret != "" && !verifyMetaSignature(a.cfg.AppSecret, body, sig) {
		log.Printf("post rejected invalid signature sig_present=%t body_len=%d", sig != "", len(body))
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	preview := string(body)
	if len(preview) > 2000 {
		preview = preview[:2000] + "..."
	}
	log.Printf("post received sig_present=%t body_len=%d payload=%s", sig != "", len(body), preview)

	var in incoming
	if err := json.Unmarshal(body, &in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	processed := 0
	for _, e := range in.Entry {
		for _, m := range e.Messaging {
			sender := m.Sender.ID
			text := strings.TrimSpace(m.Message.Text)
			if sender == "" || text == "" || m.Message.IsEcho {
				continue
			}
			processed++
			log.Printf("message accepted (messaging) sender=%s text_len=%d", sender, len(text))
			go a.processIncoming(sender, text)
		}
		for _, c := range e.Changes {
			if c.Field != "messages" {
				continue
			}
			sender := c.Value.Sender.ID
			text := strings.TrimSpace(c.Value.Message.Text)
			if sender == "" || text == "" {
				continue
			}
			processed++
			log.Printf("message accepted (changes) sender=%s text_len=%d", sender, len(text))
			go a.processIncoming(sender, text)
		}
	}
	if processed == 0 {
		preview := string(body)
		if len(preview) > 1200 {
			preview = preview[:1200] + "..."
		}
		log.Printf("post parsed entries=%d processed_messages=%d raw_preview=%s", len(in.Entry), processed, preview)
	} else {
		log.Printf("post parsed entries=%d processed_messages=%d", len(in.Entry), processed)
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
		return "Thanks for your message — we got it. A human will reply shortly.", nil
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
	if a.cfg.IGPageID == "" || a.cfg.IGPageAccessToken == "" {
		return errors.New("IG_PAGE_ID or IG_PAGE_ACCESS_TOKEN missing")
	}

	recipientID = strings.TrimSpace(recipientID)
	text = strings.TrimSpace(text)
	if recipientID == "" {
		return errors.New("recipientID missing")
	}
	if text == "" {
		return errors.New("message text missing")
	}

	payload := map[string]interface{}{
		"recipient": map[string]string{
			"id": recipientID,
		},
		"message": map[string]string{
			"text": text,
		},
		"messaging_type": "RESPONSE",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := fmt.Sprintf(
		"https://graph.facebook.com/v25.0/%s/messages",
		a.cfg.IGPageID,
	)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	q := req.URL.Query()
	q.Set("access_token", strings.TrimSpace(a.cfg.IGPageAccessToken))
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 300 {
		return fmt.Errorf("graph status=%d body=%s", resp.StatusCode, string(respBody))
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

func (a *App) handlePrivacy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html>
<html><head><meta charset="utf-8"><title>Insta Assistant Privacy Policy</title></head>
<body style="font-family:Arial,sans-serif;max-width:760px;margin:40px auto;line-height:1.6;padding:0 16px;">
<h1>Privacy Policy — Insta Assistant</h1>
<p>Effective date: 2026-04-09</p>
<p>Insta Assistant is an automation service that responds to Instagram direct messages for the connected business account.</p>
<h2>Data we process</h2>
<ul>
  <li>Instagram sender ID</li>
  <li>Message text and timestamps</li>
  <li>Webhook metadata required for message delivery and security verification</li>
</ul>
<h2>Purpose of processing</h2>
<ul>
  <li>Generate and send automated replies</li>
  <li>Maintain short conversation memory for context continuity</li>
  <li>Send optional follow-up messages if enabled</li>
</ul>
<h2>Storage and retention</h2>
<p>Conversation data is stored on a secured VPS and retained only as needed for bot operation and troubleshooting.</p>
<h2>Third-party processors</h2>
<ul>
  <li>Meta Platforms (Instagram Graph API / Webhooks)</li>
  <li>OpenAI (only when AI-generated replies are enabled)</li>
</ul>
<h2>Your rights</h2>
<p>You may request access, correction, or deletion of your data via the data deletion instructions below.</p>
<h2>Contact</h2>
<p>Email: bankolek1@gmail.com</p>
<p>Data deletion instructions: <a href="/data-deletion">/data-deletion</a></p>
</body></html>`))
}

func (a *App) handleDataDeletion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html>
<html><head><meta charset="utf-8"><title>Insta Assistant Data Deletion</title></head>
<body style="font-family:Arial,sans-serif;max-width:760px;margin:40px auto;line-height:1.6;padding:0 16px;">
<h1>Data Deletion Instructions — Insta Assistant</h1>
<p>To request deletion of your Instagram conversation data processed by Insta Assistant:</p>
<ol>
  <li>Send an email to <strong>bankolek1@gmail.com</strong> with subject: <em>Data Deletion Request</em>.</li>
  <li>Include your Instagram handle and approximate date/time of your last message.</li>
  <li>We will process and confirm deletion within 7 business days.</li>
</ol>
<p>If you are contacting from within Instagram, you may also send: <strong>DELETE MY DATA</strong> in DM to trigger manual review.</p>
</body></html>`))
}
