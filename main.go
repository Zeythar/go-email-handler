package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

type ContactRequest struct {
    Subject      string `json:"subject" form:"subject"`
    Email        string `json:"email" form:"email"`
    Message      string `json:"message" form:"message"`
    RecaptchaTok string `json:"recaptchaToken" form:"recaptchaToken"` // client must send
    // server-populated metadata (ignored if present in incoming JSON/form)
    ClientIP   string `json:"-" form:"-"`
    UserAgent  string `json:"-" form:"-"`
    ClientId   string `json:"-" form:"-"`
    RecaptchaScore  float64 `json:"-" form:"-"`
    RecaptchaAction string  `json:"-" form:"-"`
    RawXForwardedFor string `json:"-" form:"-"`
    RawRemoteAddr    string `json:"-" form:"-"`
}

// server-side validation helpers
var (
    emailRegex = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
)

// simple in-memory rate limiter (per key). For production use a centralized store.
var (
    limiterMu sync.Mutex
    limiter   = make(map[string]*clientBucket)
)

type clientBucket struct {
    Count     int
    ExpiresAt time.Time
}

const (
    maxRequestsPerWindow = 10
    windowDuration       = time.Hour
)

func allowRequest(key string) bool {
    limiterMu.Lock()
    defer limiterMu.Unlock()
    b, ok := limiter[key]
    now := time.Now()
    if !ok || now.After(b.ExpiresAt) {
        limiter[key] = &clientBucket{Count: 1, ExpiresAt: now.Add(windowDuration)}
        return true
    }
    if b.Count >= maxRequestsPerWindow {
        return false
    }
    b.Count++
    return true
}

func getIP(r *http.Request) string {
    // Prefer X-Forwarded-For if behind a proxy; otherwise remote addr
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        // may be a list, take the first
        parts := strings.Split(xff, ",")
        return strings.TrimSpace(parts[0])
    }
    host := r.RemoteAddr
    // strip port if present
    if i := strings.LastIndex(host, ":"); i != -1 {
        return host[:i]
    }
    return host
}

// verifyRecaptcha posts token to Google and returns true if valid
// verifyRecaptcha posts token to Google and returns whether verification passed,
// along with the score and action reported by Google. If RECAPTCHA_SECRET is
// not set, verification is treated as disabled (returns true, score 1.0).
func verifyRecaptcha(token string) (bool, float64, string, error) {
    secret := os.Getenv("RECAPTCHA_SECRET")
    if secret == "" {
        // treat verification as disabled for local dev
        return true, 1.0, "", nil
    }

    resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify",
        map[string][]string{
            "secret":   {secret},
            "response": {token},
        })
    if err != nil {
        return false, 0, "", err
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    var res struct {
        Success bool    `json:"success"`
        Score   float64 `json:"score"`
        Action  string  `json:"action"`
    }
    if err := json.Unmarshal(body, &res); err != nil {
        return false, 0, "", err
    }

    // Configurable threshold (env RECAPTCHA_THRESHOLD), default 0.5
    thresh := 0.5
    if ts := os.Getenv("RECAPTCHA_THRESHOLD"); ts != "" {
        if v, err := strconv.ParseFloat(ts, 64); err == nil {
            thresh = v
        }
    }

    if !res.Success {
        return false, res.Score, res.Action, nil
    }
    if res.Score < thresh {
        return false, res.Score, res.Action, nil
    }

    return true, res.Score, res.Action, nil
}

func main() {
    // Try to load .env for local development (optional)
    _ = godotenv.Load()

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    http.HandleFunc("/api/contact", contactHandler)

    srv := &http.Server{
        Addr:         ":" + port,
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 10 * time.Second,
    }

    log.Printf("Starting server on %s...", srv.Addr)
    if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
        log.Fatalf("server failed: %v", err)
    }
}

func contactHandler(w http.ResponseWriter, r *http.Request) {
    // Normalize ALLOWED_ORIGIN (allow trailing slash or none) and incoming origin
    allowedOrigin := strings.TrimRight(strings.TrimSpace(os.Getenv("ALLOWED_ORIGIN")), "/") // e.g. https://example.com
    origin := strings.TrimRight(strings.TrimSpace(r.Header.Get("Origin")), "/")
    referer := strings.TrimSpace(r.Referer())
    if allowedOrigin != "" {
        // If Origin header missing, try to derive origin from Referer
        if origin == "" && referer != "" {
            if u, err := url.Parse(referer); err == nil && u.Scheme != "" && u.Host != "" {
                origin = u.Scheme + "://" + u.Host
            }
        }
        if origin == "" || origin != allowedOrigin {
            http.Error(w, "forbidden origin", http.StatusForbidden)
            return
        }
        // Echo back the validated origin (must match request Origin)
        w.Header().Set("Access-Control-Allow-Origin", origin)
    } else {
        // fallback to permissive for local dev
        w.Header().Set("Access-Control-Allow-Origin", "*")
    }
    w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
    // Allow Content-Type and X-Client-Id by default. Also echo back any requested
    // headers from the preflight so clients can use custom headers without failing.
    defaultAllowed := "Content-Type, X-Client-Id"
    if reqHeaders := r.Header.Get("Access-Control-Request-Headers"); reqHeaders != "" {
        // combine requested headers with our defaults (deduplication is not critical here)
        w.Header().Set("Access-Control-Allow-Headers", defaultAllowed+", "+reqHeaders)
    } else {
        w.Header().Set("Access-Control-Allow-Headers", defaultAllowed)
    }
    if r.Method == http.MethodOptions {
        w.WriteHeader(http.StatusNoContent)
        return
    }

    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Prefer a client-provided id to better identify users behind shared IPs.
    // Client should send X-Client-Id header (generated and stored in localStorage by the Svelte app).
    clientId := strings.TrimSpace(r.Header.Get("X-Client-Id"))
    var key string
    if clientId != "" {
        key = clientId + "|" + getIP(r)
    } else {
        key = getIP(r)
    }
    if !allowRequest(key) {
        http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
        return
    }

    // Support JSON or form-encoded
    var req ContactRequest
    contentType := r.Header.Get("Content-Type")
    if strings.HasPrefix(contentType, "application/json") {
        dec := json.NewDecoder(r.Body)
        if err := dec.Decode(&req); err != nil {
            http.Error(w, "invalid json", http.StatusBadRequest)
            return
        }
    } else {
        if err := r.ParseForm(); err != nil {
            http.Error(w, "invalid form", http.StatusBadRequest)
            return
        }
        req.Subject = r.FormValue("subject")
        req.Email = r.FormValue("email")
        req.Message = r.FormValue("message")
        req.RecaptchaTok = r.FormValue("recaptchaToken")
    }

    // Populate server-side metadata to help detect abuse
    req.ClientIP = getIP(r)
    req.UserAgent = r.Header.Get("User-Agent")
    req.ClientId = strings.TrimSpace(r.Header.Get("X-Client-Id"))
    req.RawXForwardedFor = r.Header.Get("X-Forwarded-For")
    req.RawRemoteAddr = r.RemoteAddr

    // Basic validation
    if req.Email == "" || req.Message == "" {
        http.Error(w, "email and message are required", http.StatusBadRequest)
        return
    }

    // Validate email format
    if !emailRegex.MatchString(req.Email) {
        http.Error(w, "invalid email format", http.StatusBadRequest)
        return
    }

    // Ensure subject has a sensible default if empty
    if req.Subject == "" {
        req.Subject = "New contact form message"
    }

    // Verify captcha (if configured)
    // If the server has RECAPTCHA_SECRET configured, require a token be sent.
    if os.Getenv("RECAPTCHA_SECRET") != "" && strings.TrimSpace(req.RecaptchaTok) == "" {
        http.Error(w, "captcha required", http.StatusForbidden)
        return
    }

    ok, score, action, err := verifyRecaptcha(req.RecaptchaTok)
    if err != nil {
        log.Printf("recaptcha verify error: %v", err)
        http.Error(w, "captcha verification failed", http.StatusInternalServerError)
        return
    }
    if !ok {
        log.Printf("recaptcha failed: score=%v action=%s", score, action)
        http.Error(w, "captcha required", http.StatusForbidden)
        return
    }

    // populate request with recaptcha metadata so email can include it
    req.RecaptchaScore = score
    req.RecaptchaAction = action

    // Send email
    if err := sendEmail(req); err != nil {
        log.Printf("sendEmail error: %v", err)
        http.Error(w, "failed to send email (check server logs)", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte(`{"ok":true}`))
}

func sendEmail(c ContactRequest) error {
    // If Mailgun API is configured, prefer it (no SMTP-port egress required)
    mailgunURL := os.Getenv("MAILGUN_API_URL") // full API endpoint, e.g. https://api.eu.mailgun.net/v3/etheoo.com/messages
    mailgunKey := os.Getenv("MAILGUN_API_KEY")
    mailgunFrom := os.Getenv("MAILGUN_FROM")
    toEmail := os.Getenv("TO_EMAIL")

    // Decide From header
    from := mailgunFrom
    if from == "" {
        from = "contact-form@localhost"
    }

    if toEmail == "" {
        return fmt.Errorf("TO_EMAIL not set")
    }

    subject := c.Subject
    if subject == "" {
        subject = "New contact form message"
    }

    // include whatever was stored in c.ClientIP and c.ClientId etc.
    messageBody := fmt.Sprintf(
        "You received a new message from:\r\n"+
            "Email: %s\r\n\r\n"+
            "Message:\r\n%s\r\n\r\n"+
            "--- meta ---\r\n"+
            "Timestamp (UTC): %s\r\n"+
            "Client IP (chosen): %s\r\n"+
            "ClientId: %s\r\n"+
            "User-Agent: %s\r\n"+
            "X-Forwarded-For (raw): %s\r\n"+
            "RemoteAddr: %s\r\n"+
            "reCAPTCHA: score=%.3f action=%s\r\n",
        c.Email, c.Message, time.Now().UTC().Format(time.RFC3339), c.ClientIP, c.ClientId, c.UserAgent, c.RawXForwardedFor, c.RawRemoteAddr, c.RecaptchaScore, c.RecaptchaAction,
    )

    // Optionally log the raw reCAPTCHA interaction for debugging
    if os.Getenv("RECAPTCHA_DEBUG") != "" {
        log.Printf("recaptcha debug: token present=%v score=%.3f action=%s xff=%s remote=%s",
            c.RecaptchaScore > -1, c.RecaptchaScore, c.RecaptchaAction, c.RawXForwardedFor, c.RawRemoteAddr)
    }

    // If Mailgun API is configured, use it
    if mailgunURL != "" && mailgunKey != "" {
        form := url.Values{}
        form.Set("from", from)
        form.Set("to", toEmail)
        form.Set("subject", subject)
        form.Set("text", messageBody)

        req, err := http.NewRequest("POST", mailgunURL, strings.NewReader(form.Encode()))
        if err != nil {
            return err
        }
        req.SetBasicAuth("api", mailgunKey)
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

        client := &http.Client{Timeout: 15 * time.Second}
        resp, err := client.Do(req)
        if err != nil {
            return err
        }
        defer resp.Body.Close()
        if resp.StatusCode < 200 || resp.StatusCode >= 300 {
            b, _ := io.ReadAll(resp.Body)
            return fmt.Errorf("mailgun api error: status=%d body=%s", resp.StatusCode, string(b))
        }
        return nil
    }

    // Fallback to SMTP (existing behavior)
    smtpHost := os.Getenv("SMTP_HOST")
    smtpPort := os.Getenv("SMTP_PORT")
    smtpUser := os.Getenv("SMTP_USER")
    smtpPass := os.Getenv("SMTP_PASS")
    fromEnv := os.Getenv("SMTP_FROM") // optional override for From header

    if smtpHost == "" || smtpPort == "" {
        return fmt.Errorf("smtp configuration incomplete; set SMTP_HOST and SMTP_PORT")
    }

    // Decide envelope-from and From header (if SMTP fallback)
    if fromEnv != "" {
        from = fromEnv
    } else if smtpUser != "" {
        from = smtpUser
    }

    // Build message bytes (headers + body)
    msg := []byte(fmt.Sprintf(
        "From: %s\r\n"+
            "To: %s\r\n"+
            "Reply-To: %s\r\n"+
            "Subject: %s\r\n"+
            "MIME-Version: 1.0\r\n"+
            "Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n%s",
        from, toEmail, c.Email, subject, messageBody,
    ))

    addr := smtpHost + ":" + smtpPort

    // Prepare auth (may be nil for unauthenticated SMTP)
    var auth smtp.Auth
    if smtpUser != "" && smtpPass != "" {
        auth = smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
    }

    // SMTPS (implicit TLS on 465)
    if smtpPort == "465" {
        tlsCfg := &tls.Config{ServerName: smtpHost}
        conn, err := tls.Dial("tcp", addr, tlsCfg)
        if err != nil {
            return err
        }
        client, err := smtp.NewClient(conn, smtpHost)
        if err != nil {
            return err
        }
        defer client.Quit()

        if auth != nil {
            if err := client.Auth(auth); err != nil {
                return err
            }
        }
        if err := client.Mail(from); err != nil {
            return err
        }
        if err := client.Rcpt(toEmail); err != nil {
            return err
        }
        w, err := client.Data()
        if err != nil {
            return err
        }
        if _, err := w.Write(msg); err != nil {
            return err
        }
        if err := w.Close(); err != nil {
            return err
        }
        return client.Quit()
    }

    // For other ports (25, 587) attempt plain dial + STARTTLS if offered
    client, err := smtp.Dial(addr)
    if err != nil {
        return err
    }
    defer client.Close()

    // If server supports STARTTLS, negotiate TLS
    if ok, _ := client.Extension("STARTTLS"); ok {
        tlsCfg := &tls.Config{ServerName: smtpHost}
        if err := client.StartTLS(tlsCfg); err != nil {
            return err
        }
    }

    if auth != nil {
        if ok, _ := client.Extension("AUTH"); ok {
            if err := client.Auth(auth); err != nil {
                return err
            }
        }
    }

    if err := client.Mail(from); err != nil {
        return err
    }
    if err := client.Rcpt(toEmail); err != nil {
        return err
    }
    w, err := client.Data()
    if err != nil {
        return err
    }
    if _, err := w.Write(msg); err != nil {
        return err
    }
    if err := w.Close(); err != nil {
        return err
    }
    return client.Quit()
}