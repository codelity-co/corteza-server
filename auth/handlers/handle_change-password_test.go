package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cortezaproject/corteza-server/auth/request"
	"github.com/cortezaproject/corteza-server/pkg/options"
	"github.com/cortezaproject/corteza-server/store"
	"github.com/cortezaproject/corteza-server/store/sqlite3"
	"github.com/cortezaproject/corteza-server/system/service"
	"github.com/cortezaproject/corteza-server/system/types"
	"github.com/gorilla/sessions"
	"github.com/quasoft/memstore"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type (
	mockAuthService struct {
		authService

		store         store.Storer
		settings      *types.AppSettings
		notifications service.AuthNotificationService

		providerValidator func(string) error
	}

	prepareFn func()

	mockNotificationService struct {
		settings *types.AppSettings
		opt      options.AuthOpt
	}
)

func Test_changePasswordForm_setValues(t *testing.T) {
	var (
		ctx      = context.Background()
		memStore = memstore.NewMemStore()
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

	err := h.changePasswordForm(&authReq)

	rq.NoError(err)
	rq.Equal(TmplChangePassword, authReq.Template)
	rq.Equal(payload, authReq.Data["form"])
}

func Test_changePasswordProc(t *testing.T) {
	var (
		ctx      = context.Background()
		memStore = memstore.NewMemStore()
		rq       = require.New(t)
		user     = makeMockUser(ctx)

		userReq     *types.User
		req         *http.Request
		authService *mockAuthService

		tcc = []struct {
			name      string
			expect    interface{}
			prepareFn prepareFn
		}{
			{
				name:   "provided password is not secure",
				expect: map[string]string{"error": "provided password is not secure; use longer password with more non-alphanumeric character"},
				prepareFn: func() {
					userReq = user

					req = &http.Request{
						Header:   http.Header{},
						PostForm: make(url.Values),
					}

					req.PostForm.Add("oldPassword", "an_old_password_of_mine")
					req.PostForm.Add("newPassword", "test")

					service.CurrentSettings = &types.AppSettings{}
					service.CurrentSettings.Auth.Internal.Enabled = true
				},
			},
			{
				name:   "internal login is not enabled",
				expect: map[string]string{"error": "internal login (username/password) is disabled"},
				prepareFn: func() {
					userReq = user

					req = &http.Request{
						Header:   http.Header{},
						PostForm: make(url.Values),
					}

					req.PostForm.Add("oldPassword", "an_old_password_of_mine")
					req.PostForm.Add("newPassword", "test1")

					service.CurrentSettings = &types.AppSettings{}
					service.CurrentSettings.Auth.Internal.Enabled = false
				},
			},
			{
				name:   "password change failed old password does not match",
				expect: map[string]string{"error": "failed to change password, old password does not match"},
				prepareFn: func() {
					userReq = user

					req = &http.Request{
						Header:   http.Header{},
						PostForm: make(url.Values),
					}

					req.PostForm.Add("oldPassword", "an_old_password_of_mine_BUT_FORGOT_IT")
					req.PostForm.Add("newPassword", "test1")

					service.CurrentSettings = &types.AppSettings{}
					service.CurrentSettings.Auth.Internal.Enabled = true
				},
			},
			{
				name:   "password change failed for unknown user",
				expect: map[string]string{"error": "failed to change password for the unknown user"},
				prepareFn: func() {
					userReq = &types.User{
						ID:       2,
						Username: "mock.user",
						Email:    "mockuser@example.tld",
					}

					req = &http.Request{
						Header:   http.Header{},
						PostForm: make(url.Values),
					}

					req.PostForm.Add("oldPassword", "test42")
					req.PostForm.Add("newPassword", "test1")

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
				User:     userReq,
				Session:  sessions.NewSession(memStore, "session"),
				Response: httptest.NewRecorder(),
				Data:     make(map[string]interface{}),
			}

			err := h.changePasswordProc(&authReq)

			rq.NoError(err)
			rq.Equal(tc.expect, authReq.GetKV())
		})
	}
}

func Test_changePasswordFormProc_successfulyChanged(t *testing.T) {
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
		PostForm: url.Values{},
	}

	req.PostForm.Add("oldPassword", "an_old_password_of_mine")
	req.PostForm.Add("newPassword", "test1")

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
		User:     user,
		Session:  sessions.NewSession(memStore, "session"),
		Response: httptest.NewRecorder(),
		Data:     make(map[string]interface{}),
	}

	err := h.changePasswordProc(&authReq)

	rq.NoError(err)
	rq.Equal([]request.Alert{{Type: "primary", Text: "Password successfully changed.", Html: ""}}, authReq.NewAlerts)
	rq.Equal(map[string]string(nil), authReq.GetKV())
}

// Mock auth service with nil for current time, dummy provider validator and mock db
func makeMockAuthService(ctx context.Context) *mockAuthService {
	mem, err := sqlite3.ConnectInMemory(ctx)

	if err != nil {
		panic(err)
	}

	service.DefaultStore = mem
	service.DefaultAuthNotification = mockNotificationService{
		settings: service.CurrentSettings,
		opt:      options.AuthOpt{},
	}

	if err = store.Upgrade(ctx, zap.NewNop(), mem); err != nil {
		panic(err)
	}

	serviceAuth := service.Auth()

	svc := mockAuthService{
		authService: serviceAuth,
		settings:    service.CurrentSettings,
		providerValidator: func(s string) error {
			// All providers are valid.
			return nil
		},
		store: mem,
	}

	return &svc
}

func makeMockAuthService2(ctx context.Context, storer store.Storer) *mockAuthService {
	service.DefaultStore = storer
	service.DefaultAuthNotification = mockNotificationService{
		settings: service.CurrentSettings,
		opt:      options.AuthOpt{},
	}

	if err := store.Upgrade(ctx, zap.NewNop(), storer); err != nil {
		panic(err)
	}

	serviceAuth := service.Auth()

	svc := mockAuthService{
		authService: serviceAuth,
		settings:    service.CurrentSettings,
		providerValidator: func(s string) error {
			// All providers are valid.
			return nil
		},
		store: storer,
	}

	return &svc
}

func makeMockUser(ctx context.Context) *types.User {
	return &types.User{
		ID:       1,
		Username: "mock.user",
		Email:    "mockuser@example.tld",
	}
}

func (ma mockAuthService) ValidatePasswordResetToken(ctx context.Context, token string) (*types.User, error) {
	return &types.User{ID: 123}, nil
}

func (m mockNotificationService) EmailConfirmation(ctx context.Context, lang string, emailAddress string, url string) error {
	return nil
}

func (m mockNotificationService) PasswordReset(ctx context.Context, lang string, emailAddress string, url string) error {
	return nil
}
