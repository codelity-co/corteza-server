package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cortezaproject/corteza-server/auth/request"
	"github.com/cortezaproject/corteza-server/auth/settings"
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
		ctx      = context.Background()
		memStore = memstore.NewMemStore()
		user     = makeMockUser(ctx)

		req = &http.Request{
			Header:   http.Header{},
			PostForm: make(url.Values),
		}

		authService  *mockAuthService
		authHandlers *AuthHandlers
		authReq      *request.AuthReq

		rq = require.New(t)
	)

	mem := initStore(ctx, t)

	service.CurrentSettings = &types.AppSettings{}
	service.CurrentSettings.Auth.Internal.Enabled = true

	authSettings := &settings.Settings{}

	authService = prepareClientAuthService(ctx, mem, user, memStore)
	authReq = prepareClientAuthReq(ctx, req, user, memStore)
	authHandlers = prepareClientAuthHandlers(ctx, authService, authSettings)

	payload := map[string]string{"key": "value"}
	authReq.SetKV(payload)

	authHandlers.Settings = &settings.Settings{
		EmailConfirmationRequired: true,
	}

	err := authHandlers.loginForm(authReq)

	rq.NoError(err)
	rq.Equal(TmplLogin, authReq.Template)
	rq.Equal(payload, authReq.Data["form"])
}

func Test_loginProc(t *testing.T) {
	var (
		ctx      = context.Background()
		memStore = memstore.NewMemStore()
		user     = makeMockUser(ctx)

		req = &http.Request{}

		authService  *mockAuthService
		authHandlers *AuthHandlers
		authReq      *request.AuthReq

		authSettings = &settings.Settings{}

		rq = require.New(t)
	)

	mem := initStore(ctx, t)

	service.CurrentSettings = &types.AppSettings{}

	var (
		tcc = []testingExpect{
			{
				name:    "successful login",
				payload: map[string]string(nil),
				alerts:  []request.Alert{{Type: "primary", Text: "You are now logged-in", Html: ""}},
				link:    GetLinks().Profile,
				fn: func() {
					service.CurrentSettings.Auth.Internal.Enabled = true
					req.PostForm.Add("email", "mockuser@example.tld")
					req.PostForm.Add("password", "an_old_password_of_mine")
				},
			},
			{
				name:    "internal login is not enabled",
				payload: map[string]string(nil),
				alerts:  []request.Alert{{Type: "danger", Text: "Local accounts disabled", Html: ""}},
				link:    GetLinks().Profile,
				fn: func() {
					service.CurrentSettings.Auth.Internal.Enabled = false
				},
			},
			{
				name:    "invalid email format",
				payload: map[string]string{"email": "email@", "error": "invalid email"},
				alerts:  []request.Alert(nil),
				link:    GetLinks().Login,
				fn: func() {
					req.PostForm.Add("email", "email@")
					service.CurrentSettings.Auth.Internal.Enabled = true
				},
			},
			{
				name:    "invalid credentials",
				payload: map[string]string{"email": "mockuser@example.tld", "error": "invalid username and password combination"},
				alerts:  []request.Alert(nil),
				link:    GetLinks().Login,
				fn: func() {
					req.PostForm.Add("email", "mockuser@example.tld")
					req.PostForm.Add("password", "an_old_password_of_mine_BUT_FORGOT_IT")
					service.CurrentSettings.Auth.Internal.Enabled = true
				},
			},
			{
				name:    "credentials linked to invalid user",
				payload: map[string]string{"email": "mockuser@example.tld", "error": "invalid username and password combination"},
				alerts:  []request.Alert(nil),
				link:    GetLinks().Login,
				fn: func() {
					req.PostForm.Add("email", "mockuser@example.tld")
					req.PostForm.Add("password", "an_old_password_of_mine")
					service.CurrentSettings.Auth.Internal.Enabled = true
					user.SuspendedAt = now()
				},
			},
			{
				name:    "PendingEmailOTP",
				payload: map[string]string{"email": "mockuser@example.tld", "error": "invalid username and password combination"},
				alerts:  []request.Alert(nil),
				link:    GetLinks().Login,
				fn: func() {
					req.PostForm.Add("email", "mockuser@example.tld")
					req.PostForm.Add("password", "an_old_password_of_mine")
					service.CurrentSettings.Auth.Internal.Enabled = true
					authSettings.MultiFactor.EmailOTP.Enabled = true
					authSettings.MultiFactor.EmailOTP.Enforced = true
				},
			},
		}
	)

	for _, tc := range tcc {
		t.Run(tc.name, func(t *testing.T) {
			// reset from previous
			req.PostForm = url.Values{}

			tc.fn()

			authService = prepareClientAuthService(ctx, mem, user, memStore)
			authReq = prepareClientAuthReq(ctx, req, user, memStore)
			authHandlers = prepareClientAuthHandlers(ctx, authService, authSettings)

			authHandlers.UserService = tc.userService
			authService.store.TruncateUsers(ctx)
			authService.store.CreateUser(ctx, user)
			authService.SetPassword(ctx, user.ID, "an_old_password_of_mine")

			err := authHandlers.loginProc(authReq)

			rq.NoError(err)
			rq.Equal(tc.payload, authReq.GetKV())
			rq.Equal(tc.alerts, authReq.NewAlerts)
			rq.Equal(tc.link, authReq.RedirectTo)
		})
	}
	// t.Fail()
}

func Test_loginProc_successfulLoginOauth2Params(t *testing.T) {
	var (
		ctx      = context.Background()
		memStore = memstore.NewMemStore()
		rq       = require.New(t)
		user     = makeMockUser(ctx)

		req         *http.Request
		authService *mockAuthService
	)

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

	authUser := request.NewAuthUser(&settings.Settings{}, user, true, time.Duration(time.Hour))

	h := AuthHandlers{
		Log:         zap.NewNop(),
		AuthService: authService,
	}

	sess := sessions.NewSession(memStore, "session")
	sess.Values = map[interface{}]interface{}{"oauth2AuthParams": url.Values{}}

	authReq := request.AuthReq{
		Request:  req,
		AuthUser: authUser,
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

// wrapper around time.Now() that will aid service testing
func now() *time.Time {
	c := time.Now()
	// c := time.Now().Round(time.Second)
	return &c
}
