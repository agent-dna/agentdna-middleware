package handler

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"agentdna-ratelimit-auth/db"
	"agentdna-ratelimit-auth/email"

	"github.com/gin-gonic/gin"
)

const (
	// Login OTPs live under their own key, so a code sent for another purpose
	// (e.g. /forgot-password) can't be used to sign in, and vice versa.
	loginOTPKeyPrefix = "login:"
	loginOTPTTL       = 5 * time.Minute
	// loginOTPResendAfter is how long a user waits before another code can be
	// emailed, so the endpoint can't be used to flood an inbox.
	loginOTPResendAfter = 60 * time.Second

	msgEmailNotRegistered = "this email is not registered, please register first"
)

func loginOTPKey(emailAddr string) string { return loginOTPKeyPrefix + emailAddr }

// SendLoginOTP handles POST /dashboard/v1/login/send-otp {email}: emails a
// one-time code an org user signs in with via /login/verify-otp. An email with
// no account gets 404 with data.registered=false, so the dashboard can send
// the user to registration.
func (h *Handler) SendLoginOTP(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Email) == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "email is required"})
		return
	}
	emailAddr := strings.TrimSpace(req.Email)

	if _, err := h.db.GetOrgUserByEmail(emailAddr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Printf("[SendLoginOTP] email not registered email=%q", emailAddr)
			c.JSON(http.StatusNotFound, Response{Status: false, Message: msgEmailNotRegistered, Data: gin.H{"registered": false}})
			return
		}
		log.Printf("[SendLoginOTP] user lookup failed email=%q err=%v", emailAddr, err)
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to look up user"})
		return
	}

	key := loginOTPKey(emailAddr)
	if val, ok := h.otpStore.Load(key); ok {
		entry := val.(otpEntry)
		if wait := loginOTPResendAfter - time.Since(entry.issuedAt); wait > 0 && time.Now().Before(entry.expiresAt) {
			secs := int(wait.Round(time.Second).Seconds())
			c.JSON(http.StatusTooManyRequests, Response{Status: false,
				Message: fmt.Sprintf("an OTP was just sent, please wait %d seconds before requesting another", secs),
				Data:    gin.H{"retryAfterSeconds": secs}})
			return
		}
	}

	code, err := generateOTP()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to generate OTP"})
		return
	}
	now := time.Now()
	h.otpStore.Store(key, otpEntry{code: code, issuedAt: now, expiresAt: now.Add(loginOTPTTL)})

	h.sendMail(email.LoginOTP(emailAddr, code))
	log.Printf("[SendLoginOTP] OTP sent to email=%q", emailAddr)
	c.JSON(http.StatusOK, Response{Status: true, Message: "OTP sent to " + emailAddr})
}

// VerifyLoginOTP handles POST /dashboard/v1/login/verify-otp {email, otp}: on
// a correct code it starts the same session /login does and returns the same
// body. Failures are 400, not 401: the dashboard reads 401 as "session
// expired" and would hide the message.
func (h *Handler) VerifyLoginOTP(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
		OTP   string `json:"otp"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Email) == "" || strings.TrimSpace(req.OTP) == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "email and otp are required"})
		return
	}
	emailAddr := strings.TrimSpace(req.Email)

	if !h.verifyOTP(loginOTPKey(emailAddr), strings.TrimSpace(req.OTP)) {
		log.Printf("[VerifyLoginOTP] invalid or expired OTP email=%q", emailAddr)
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "invalid or expired OTP"})
		return
	}

	// Looked up after the OTP check: the account may have gone since the code
	// was sent.
	user, err := h.db.GetOrgUserByEmail(emailAddr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, Response{Status: false, Message: msgEmailNotRegistered, Data: gin.H{"registered": false}})
			return
		}
		log.Printf("[VerifyLoginOTP] user lookup failed email=%q err=%v", emailAddr, err)
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to look up user"})
		return
	}

	if err := h.startSession(c, db.SessionAccountUser, user.Email); err != nil {
		log.Printf("[VerifyLoginOTP] create session failed email=%q err=%v", emailAddr, err)
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to create session"})
		return
	}
	log.Printf("[VerifyLoginOTP] user login success email=%q did=%q", user.Email, user.DID)
	c.JSON(http.StatusOK, Response{Status: true, Data: userLoginData(user)})
}
