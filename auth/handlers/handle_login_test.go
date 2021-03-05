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

type (
	expectPayload struct {
		kv    map[string]string
		alert []request.Alert
	}
)

func Test_loginForm_setValues(t *testing.T) {
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

	err := h.loginForm(&authReq)

	rq.NoError(err)
	rq.Equal(TmplLogin, authReq.Template)
	rq.Equal(payload, authReq.Data["form"])
}

func Test_loginProc(t *testing.T) {
	var (
		ctx      = context.Background()
		memStore = memstore.NewMemStore()
		rq       = require.New(t)
		user     = makeMockUser(ctx)

		req         *http.Request
		authService *mockAuthService

		tcc = []struct {
			name      string
			expect    expectPayload
			prepareFn prepareFn
		}{
			{
				name: "internal login is not enabled",
				expect: expectPayload{
					kv:    map[string]string(nil),
					alert: []request.Alert{{Type: "danger", Text: "Local accounts disabled", Html: ""}},
				},
				prepareFn: func() {
					req = &http.Request{
						Header:   http.Header{},
						PostForm: make(url.Values),
					}

					service.CurrentSettings = &types.AppSettings{}
					service.CurrentSettings.Auth.Internal.Enabled = false
				},
			},
			{
				name: "invalid email format",
				expect: expectPayload{
					kv:    map[string]string{"email": "email@", "error": "invalid email"},
					alert: []request.Alert(nil),
				},
				prepareFn: func() {
					req = &http.Request{
						Header:   http.Header{},
						PostForm: make(url.Values),
					}

					req.PostForm.Add("email", "email@")

					service.CurrentSettings = &types.AppSettings{}
					service.CurrentSettings.Auth.Internal.Enabled = true
				},
			},
			{
				name: "invalid credentials",
				expect: expectPayload{
					kv:    map[string]string{"email": "mockuser@example.tld", "error": "invalid username and password combination"},
					alert: []request.Alert(nil),
				},
				prepareFn: func() {
					req = &http.Request{
						Header:   http.Header{},
						PostForm: make(url.Values),
					}

					req.PostForm.Add("email", "mockuser@example.tld")
					req.PostForm.Add("password", "an_old_password_of_mine_BUT_FORGOT_IT")

					service.CurrentSettings = &types.AppSettings{}
					service.CurrentSettings.Auth.Internal.Enabled = true
				},
			},
		}
	)

	for _, tc := range tcc {
		t.Run(tc.name, func(t *testing.T) {
			tc.prepareFn()

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
				User:     user,
				Session:  sessions.NewSession(memStore, "session"),
				Response: httptest.NewRecorder(),
				Data:     make(map[string]interface{}),
			}

			err := h.loginProc(&authReq)

			rq.NoError(err)
			rq.Equal(tc.expect.kv, authReq.GetKV())
			rq.Equal(tc.expect.alert, authReq.NewAlerts)
		})
	}

	t.Fail()
}

func Test_loginProc_successfulLogin(t *testing.T) {
	var (
		ctx      = context.Background()
		memStore = memstore.NewMemStore()
		rq       = require.New(t)
		user     = makeMockUser(ctx)

		userReq     *types.User
		req         *http.Request
		authService *mockAuthService
	)

	userReq = user

	req = &http.Request{
		Header:   http.Header{},
		PostForm: make(url.Values),
	}

	req.PostForm.Add("email", "mockuser@example.tld")
	req.PostForm.Add("password", "an_old_password_of_mine")

	service.CurrentSettings = &types.AppSettings{}
	service.CurrentSettings.Auth.Internal.Enabled = true

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
		User:     userReq,
		Session:  sessions.NewSession(memStore, "session"),
		Response: httptest.NewRecorder(),
		Data:     make(map[string]interface{}),
	}

	err := h.loginProc(&authReq)

	rq.NoError(err)
	rq.Equal(GetLinks().Profile, authReq.RedirectTo)
	rq.Equal(map[string]string(nil), authReq.GetKV())
	rq.Equal([]request.Alert{{Type: "primary", Text: "You are now logged-in", Html: ""}}, authReq.NewAlerts)
}

func Test_loginProc_successfulLoginOauth2Params(t *testing.T) {
	var (
		ctx      = context.Background()
		memStore = memstore.NewMemStore()
		rq       = require.New(t)
		user     = makeMockUser(ctx)

		userReq     *types.User
		req         *http.Request
		authService *mockAuthService
	)

	userReq = user

	req = &http.Request{
		Header:   http.Header{},
		PostForm: make(url.Values),
	}

	req.PostForm.Add("email", "mockuser@example.tld")
	req.PostForm.Add("password", "an_old_password_of_mine")

	service.CurrentSettings = &types.AppSettings{}
	service.CurrentSettings.Auth.Internal.Enabled = true

	authService = makeMockAuthService(ctx)
	authService.store.TruncateUsers(ctx)
	authService.store.CreateUser(ctx, user)
	authService.SetPassword(ctx, user.ID, "an_old_password_of_mine")

	h := AuthHandlers{
		Log:         zap.NewNop(),
		AuthService: authService,
	}

	sess := sessions.NewSession(memStore, "session")
	sess.Values = map[interface{}]interface{}{"oauth2AuthParams": url.Values{}}

	authReq := request.AuthReq{
		Request:  req,
		User:     userReq,
		Session:  sess,
		Response: httptest.NewRecorder(),
		Data:     make(map[string]interface{}),
	}

	err := h.loginProc(&authReq)

	rq.NoError(err)
	rq.Equal(GetLinks().OAuth2AuthorizeClient, authReq.RedirectTo)
	rq.Equal(map[string]string(nil), authReq.GetKV())
	rq.Equal([]request.Alert{{Type: "primary", Text: "You are now logged-in", Html: ""}}, authReq.NewAlerts)
}
