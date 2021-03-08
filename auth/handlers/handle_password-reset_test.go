package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cortezaproject/corteza-server/auth/request"
	"github.com/cortezaproject/corteza-server/system/service"
	"github.com/cortezaproject/corteza-server/system/types"
	"github.com/gorilla/sessions"
	"github.com/quasoft/memstore"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func Test_requestPasswordResetForm_setValues(t *testing.T) {
	var (
		memStore = memstore.NewMemStore()
		ctx      = context.Background()
		rq       = require.New(t)

		req         *http.Request
		authService *mockAuthService
	)

	req = &http.Request{
		Header:   http.Header{},
		PostForm: url.Values{},
	}

	service.CurrentSettings = &types.AppSettings{}

	authService = makeMockAuthService(ctx)

	h := AuthHandlers{
		Log:         zap.NewNop(),
		AuthService: authService,
	}

	authReq := request.AuthReq{
		Request:  req,
		Session:  sessions.NewSession(memStore, "session"),
		Response: httptest.NewRecorder(),
		Data:     make(map[string]interface{}),
	}

	payload := map[string]string{"key": "value"}
	authReq.SetKV(payload)

	err := h.requestPasswordResetForm(&authReq)

	rq.NoError(err)
	rq.Equal(TmplRequestPasswordReset, authReq.Template)
	rq.Equal(payload, authReq.Data["form"])
}

func Test_requestPasswordReset(t *testing.T) {
	var (
		ctx      = context.Background()
		memStore = memstore.NewMemStore()
		user     = makeMockUser(ctx)

		req         *http.Request
		authService *mockAuthService
	)

	// t.Run("proc", func(t *testing.T) {
	// 	rq := require.New(t)
	// 	req = &http.Request{
	// 		Header:   http.Header{},
	// 		PostForm: make(url.Values),
	// 	}

	// 	req.PostForm.Add("email", "mockuser@example.tld")

	// 	service.CurrentSettings = &types.AppSettings{}
	// 	service.CurrentSettings.Auth.Internal.Enabled = true
	// 	service.CurrentSettings.Auth.Internal.PasswordReset.Enabled = true

	// 	authService = makeMockAuthService(ctx)
	// 	authService.store.TruncateUsers(ctx)
	// 	authService.store.CreateUser(ctx, user)
	// 	authService.SetPassword(ctx, user.ID, "an_old_password_of_mine")

	// 	h := AuthHandlers{
	// 		Log:         zap.NewNop(),
	// 		AuthService: authService,
	// 	}

	// 	authReq := request.AuthReq{
	// 		Request:  req,
	// 		User:     user,
	// 		Session:  sessions.NewSession(memStore, "session"),
	// 		Response: httptest.NewRecorder(),
	// 		Data:     make(map[string]interface{}),
	// 	}

	// 	err := h.requestPasswordResetProc(&authReq)

	// 	rq.NoError(err)
	// 	rq.Equal(GetLinks().PasswordResetRequested, authReq.RedirectTo)
	// })

	// t.Run("form", func(t *testing.T) {
	// 	rq := require.New(t)
	// 	req = &http.Request{
	// 		Header:   http.Header{},
	// 		PostForm: make(url.Values),
	// 	}

	// 	req.PostForm.Add("email", "mockuser@example.tld")

	// 	service.CurrentSettings = &types.AppSettings{}
	// 	service.CurrentSettings.Auth.Internal.Enabled = true
	// 	service.CurrentSettings.Auth.Internal.PasswordReset.Enabled = true

	// 	authService = makeMockAuthService(ctx)
	// 	authService.store.TruncateUsers(ctx)
	// 	authService.store.CreateUser(ctx, user)
	// 	authService.SetPassword(ctx, user.ID, "an_old_password_of_mine")

	// 	h := AuthHandlers{
	// 		Log:         zap.NewNop(),
	// 		AuthService: authService,
	// 	}

	// 	authReq := request.AuthReq{
	// 		Request:  req,
	// 		User:     user,
	// 		Session:  sessions.NewSession(memStore, "session"),
	// 		Response: httptest.NewRecorder(),
	// 		Data:     make(map[string]interface{}),
	// 	}

	// 	payload := map[string]string{"key": "value"}
	// 	authReq.SetKV(payload)

	// 	err := h.resetPasswordForm(&authReq)

	// 	rq.NoError(err)
	// 	rq.Equal(TmplResetPassword, authReq.Template)
	// 	rq.Equal(payload, authReq.Data["form"])
	// })

	t.Run("form empty token", func(t *testing.T) {
		rq := require.New(t)

		tokenUrl, _ := url.Parse("?token=")
		req = &http.Request{
			Header:   http.Header{},
			PostForm: make(url.Values),
			URL:      tokenUrl,
		}

		service.CurrentSettings = &types.AppSettings{}
		service.CurrentSettings.Auth.Internal.Enabled = true
		service.CurrentSettings.Auth.Internal.PasswordReset.Enabled = true

		authService = makeMockAuthService(ctx)
		authService.store.TruncateUsers(ctx)
		authService.store.CreateUser(ctx, user)
		authService.SetPassword(ctx, user.ID, "an_old_password_of_mine")

		h := AuthHandlers{
			Log:         zap.NewNop(),
			AuthService: authService,
		}

		authReq := request.AuthReq{
			Request:  req,
			Session:  sessions.NewSession(memStore, "session"),
			Response: httptest.NewRecorder(),
			Data:     make(map[string]interface{}),
		}

		payload := map[string]string{"key": "value"}
		authReq.SetKV(payload)

		err := h.resetPasswordForm(&authReq)

		rq.NoError(err)
		rq.Equal(TmplResetPassword, authReq.Template)
		rq.Equal(payload, authReq.Data["form"])
		rq.Equal(GetLinks().RequestPasswordReset, authReq.RedirectTo)
		rq.Equal([]request.Alert([]request.Alert{{Type: "warning", Text: "Invalid or expired password reset token, please repeat password reset request.", Html: ""}}), authReq.NewAlerts)
	})

	t.Run("form valid token", func(t *testing.T) {
		rq := require.New(t)

		tokenUrl, _ := url.Parse("?token=456")
		req = &http.Request{
			Header:   http.Header{},
			PostForm: make(url.Values),
			URL:      tokenUrl,
		}

		service.CurrentSettings = &types.AppSettings{}
		service.CurrentSettings.Auth.Internal.Enabled = true
		service.CurrentSettings.Auth.Internal.PasswordReset.Enabled = true

		authService = makeMockAuthService(ctx)
		authService.store.TruncateUsers(ctx)
		authService.store.CreateUser(ctx, user)
		authService.SetPassword(ctx, user.ID, "an_old_password_of_mine")

		h := AuthHandlers{
			Log:         zap.NewNop(),
			AuthService: authService,
		}

		authReq := request.AuthReq{
			Request:  req,
			Session:  sessions.NewSession(memStore, "session"),
			Response: httptest.NewRecorder(),
			Data:     make(map[string]interface{}),
		}

		payload := map[string]string{"key": "value"}
		authReq.SetKV(payload)

		err := h.resetPasswordForm(&authReq)

		rq.NoError(err)
		rq.Equal(TmplResetPassword, authReq.Template)
		rq.Equal(uint64(123), authReq.User.ID)
		rq.Equal(GetLinks().ResetPassword, authReq.RedirectTo)
	})

	t.Run("reset password proc success", func(t *testing.T) {
		rq := require.New(t)

		tokenUrl, _ := url.Parse("?token=123")
		req = &http.Request{
			Header:   http.Header{},
			PostForm: make(url.Values),
			URL:      tokenUrl,
		}

		req.PostForm.Add("password", "an_old_password_of_mine")

		service.CurrentSettings = &types.AppSettings{}
		service.CurrentSettings.Auth.Internal.Enabled = true
		service.CurrentSettings.Auth.Internal.PasswordReset.Enabled = true

		authService = makeMockAuthService(ctx)
		authService.store.TruncateUsers(ctx)
		authService.store.CreateUser(ctx, user)
		authService.SetPassword(ctx, user.ID, "an_old_password_of_mine")

		h := AuthHandlers{
			Log:         zap.NewNop(),
			AuthService: authService,
		}

		authReq := request.AuthReq{
			Request:  req,
			Session:  sessions.NewSession(memStore, "session"),
			Response: httptest.NewRecorder(),
			Data:     make(map[string]interface{}),
			User:     user,
		}

		payload := map[string]string{"key": "value"}
		authReq.SetKV(payload)

		err := h.resetPasswordProc(&authReq)

		rq.NoError(err)
		rq.Equal([]request.Alert{{Type: "primary", Text: "Password successfully reset.", Html: ""}}, authReq.NewAlerts)
		rq.Equal(GetLinks().Profile, authReq.RedirectTo)
	})

	t.Run("reset password proc disabled", func(t *testing.T) {
		rq := require.New(t)

		tokenUrl, _ := url.Parse("?token=123")
		req = &http.Request{
			Header:   http.Header{},
			PostForm: make(url.Values),
			URL:      tokenUrl,
		}

		req.PostForm.Add("password", "an_old_password_of_mine")

		service.CurrentSettings = &types.AppSettings{}
		service.CurrentSettings.Auth.Internal.Enabled = true
		service.CurrentSettings.Auth.Internal.PasswordReset.Enabled = false

		authService = makeMockAuthService(ctx)
		authService.store.TruncateUsers(ctx)
		authService.store.CreateUser(ctx, user)
		authService.SetPassword(ctx, user.ID, "an_old_password_of_mine")

		h := AuthHandlers{
			Log:         zap.NewNop(),
			AuthService: authService,
		}

		authReq := request.AuthReq{
			Request:  req,
			Session:  sessions.NewSession(memStore, "session"),
			Response: httptest.NewRecorder(),
			Data:     make(map[string]interface{}),
			User:     user,
		}

		payload := map[string]string{"key": "value"}
		authReq.SetKV(payload)

		err := h.resetPasswordProc(&authReq)

		rq.NoError(err)
		rq.Equal([]request.Alert{{Type: "danger", Text: "Password reset disabled", Html: ""}}, authReq.NewAlerts)
		rq.Equal(GetLinks().Login, authReq.RedirectTo)
	})
	t.Fail()
}
