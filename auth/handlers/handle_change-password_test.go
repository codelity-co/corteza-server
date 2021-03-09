package handlers

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/cortezaproject/corteza-server/auth/request"
	"github.com/cortezaproject/corteza-server/auth/settings"
	"github.com/cortezaproject/corteza-server/pkg/options"
	"github.com/cortezaproject/corteza-server/store"
	"github.com/cortezaproject/corteza-server/store/sqlite3"
	"github.com/cortezaproject/corteza-server/system/service"
	"github.com/cortezaproject/corteza-server/system/types"
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
		user     = makeMockUser(ctx)

		req = &http.Request{}

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

	err := authHandlers.changePasswordForm(authReq)

	rq.NoError(err)
	rq.Equal(TmplChangePassword, authReq.Template)
	rq.Equal(payload, authReq.Data["form"])

}

func Test_changePasswordProc(t *testing.T) {
	var (
		ctx      = context.Background()
		memStore = memstore.NewMemStore()
		user     = makeMockUser(ctx)

		req = &http.Request{}

		authService  *mockAuthService
		authHandlers *AuthHandlers
		authReq      *request.AuthReq

		rq = require.New(t)

		authSettings = &settings.Settings{}

		tcc = []testingExpect{
			{
				name:    "successful password change",
				payload: map[string]string(nil),
				alerts:  []request.Alert{{Type: "primary", Text: "Password successfully changed.", Html: ""}},
				fn: func() {
					req.PostForm.Add("oldPassword", "an_old_password_of_mine")
					req.PostForm.Add("newPassword", "test1")
					service.CurrentSettings.Auth.Internal.Enabled = true
				},
			},
			{
				name:    "provided password is not secure",
				payload: map[string]string{"error": "provided password is not secure; use longer password with more non-alphanumeric character"},
				fn: func() {
					req.PostForm.Add("oldPassword", "an_old_password_of_mine")
					req.PostForm.Add("newPassword", "test")
					service.CurrentSettings.Auth.Internal.Enabled = true
				},
			},
			{
				name:    "internal login is not enabled",
				payload: map[string]string{"error": "internal login (username/password) is disabled"},
				fn: func() {
					req.PostForm.Add("oldPassword", "an_old_password_of_mine")
					req.PostForm.Add("newPassword", "test1")
					service.CurrentSettings.Auth.Internal.Enabled = false
				},
			},
			{
				name:    "password change failed old password does not match",
				payload: map[string]string{"error": "failed to change password, old password does not match"},
				fn: func() {
					req.PostForm.Add("oldPassword", "an_old_password_of_mine_BUT_FORGOT_IT")
					req.PostForm.Add("newPassword", "test1")
					service.CurrentSettings.Auth.Internal.Enabled = true
				},
			},
			{
				name:    "password change failed for unknown user",
				payload: map[string]string{"error": "failed to change password for the unknown user"},
				fn: func() {
					// userReq = &types.User{
					// 	ID:       2,
					// 	Username: "mock.user",
					// 	Email:    "mockuser@example.tld",
					// }
					req.PostForm.Add("oldPassword", "test42")
					req.PostForm.Add("newPassword", "test1")
					service.CurrentSettings.Auth.Internal.Enabled = true
				},
			},
		}
	)

	mem := initStore(ctx, t)

	service.CurrentSettings = &types.AppSettings{}

	for _, tc := range tcc {
		t.Run(tc.name, func(t *testing.T) {
			req.PostForm = url.Values{}

			tc.fn()

			authService = prepareClientAuthService(ctx, mem, user, memStore)
			authReq = prepareClientAuthReq(ctx, req, user, memStore)
			authHandlers = prepareClientAuthHandlers(ctx, authService, authSettings)

			authHandlers.UserService = tc.userService
			authService.store.TruncateUsers(ctx)
			authService.store.CreateUser(ctx, user)
			authService.SetPassword(ctx, user.ID, "an_old_password_of_mine")

			err := authHandlers.changePasswordProc(authReq)

			rq.NoError(err)
			rq.Equal(tc.payload, authReq.GetKV())

			if tc.alerts != nil {
				rq.Equal(tc.alerts, authReq.NewAlerts)
			}
		})
	}
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
	u := &types.User{ID: 1, Username: "mock.user", Email: "mockuser@example.tld", Meta: &types.UserMeta{}}
	u.Meta.SecurityPolicy.MFA.EnforcedEmailOTP = true
	u.Meta.SecurityPolicy.MFA.EnforcedTOTP = false

	return u
}

func (ma mockAuthService) ValidatePasswordResetToken(ctx context.Context, token string) (*types.User, error) {
	return &types.User{ID: 123}, nil
}

func (ma mockAuthService) SendEmailOTP(ctx context.Context) error {
	return nil
}

func (m mockNotificationService) EmailConfirmation(ctx context.Context, lang string, emailAddress string, url string) error {
	return nil
}

func (m mockNotificationService) PasswordReset(ctx context.Context, lang string, emailAddress string, url string) error {
	return nil
}

func (m mockNotificationService) EmailOTP(ctx context.Context, lang string, emailAddress string, otp string) error {
	return nil
}
