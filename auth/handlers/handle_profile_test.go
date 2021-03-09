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
	userServiceUpdateSuccess            struct{}
	userServiceUpdateInvalidID          struct{}
	userServiceUpdateInvalidHandle      struct{}
	userServiceUpdateInvalidEmail       struct{}
	userServiceUpdateHandleNotUnique    struct{}
	userServiceUpdateNotAllowedToUpdate struct{}

	testingExpect struct {
		name        string
		payload     interface{}
		link        string
		err         string
		alerts      []request.Alert
		userService userService
		fn          func()
	}
)

func Test_profileForm_setValues(t *testing.T) {
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
	authReq.Data = make(map[string]interface{})

	authHandlers.Settings = &settings.Settings{
		EmailConfirmationRequired: true,
	}

	err := authHandlers.profileForm(authReq)

	rq.NoError(err)
	rq.Equal(TmplProfile, authReq.Template)
	rq.Equal(payload, authReq.Data["form"])
	rq.Equal(true, authReq.Data["emailConfirmationRequired"])
}

func Test_profileForm(t *testing.T) {
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

	tcc := []testingExpect{
		{
			name:        "proc",
			err:         "",
			userService: &userServiceUpdateSuccess{},
			alerts:      []request.Alert{{Type: "primary", Text: "Profile successfully updated.", Html: ""}},
			link:        GetLinks().Profile,
		},
		{
			name:        "proc invalid ID",
			err:         "invalid ID",
			userService: &userServiceUpdateInvalidID{},
			alerts:      []request.Alert{{Type: "danger", Text: "Could not update profile due to input errors", Html: ""}},
			link:        GetLinks().Profile,
		},
		{
			name:        "proc invalid handle",
			err:         "invalid handle",
			userService: &userServiceUpdateInvalidHandle{},
			alerts:      []request.Alert{{Type: "danger", Text: "Could not update profile due to input errors", Html: ""}},
			link:        GetLinks().Profile,
		},
		{
			name:        "proc invalid email",
			err:         "invalid email",
			userService: &userServiceUpdateInvalidEmail{},
			alerts:      []request.Alert{{Type: "danger", Text: "Could not update profile due to input errors", Html: ""}},
			link:        GetLinks().Profile,
		},
		{
			name:        "proc handle not unique",
			err:         "handle not unique",
			userService: &userServiceUpdateHandleNotUnique{},
			alerts:      []request.Alert{{Type: "danger", Text: "Could not update profile due to input errors", Html: ""}},
			link:        GetLinks().Profile,
		},
		{
			name:        "proc not allowed to update",
			err:         "not allowed to update this user",
			userService: &userServiceUpdateNotAllowedToUpdate{},
			alerts:      []request.Alert{{Type: "danger", Text: "Could not update profile due to input errors", Html: ""}},
			link:        GetLinks().Profile,
		},
	}

	for _, tc := range tcc {
		t.Run(tc.name, func(t *testing.T) {
			authSettings := &settings.Settings{}

			authService = prepareClientAuthService(ctx, mem, user, memStore)
			authReq = prepareClientAuthReq(ctx, req, user, memStore)
			authHandlers = prepareClientAuthHandlers(ctx, authService, authSettings)

			authHandlers.UserService = tc.userService
			authService.store.TruncateUsers(ctx)
			authService.store.CreateUser(ctx, user)
			authService.SetPassword(ctx, user.ID, "an_old_password_of_mine")

			authHandlers.profileProc(authReq)

			rq.Equal(tc.err, authReq.GetKV()["error"])
			rq.Equal(tc.alerts, authReq.NewAlerts)
			rq.Equal(tc.link, authReq.RedirectTo)
		})
	}
}

func prepareClientAuthReq(ctx context.Context, req *http.Request, user *types.User, memStore *memstore.MemStore) *request.AuthReq {
	// todo use parameter for settings
	s := &settings.Settings{}

	s.MultiFactor.EmailOTP.Enabled = true
	s.MultiFactor.EmailOTP.Enforced = true
	s.MultiFactor.TOTP.Enabled = true

	authUser := request.NewAuthUser(s, user, true, time.Duration(time.Hour))

	return &request.AuthReq{
		Request:  req,
		AuthUser: authUser,
		Session:  sessions.NewSession(memStore, "session"),
		Response: httptest.NewRecorder(),
		Data:     make(map[string]interface{}),
	}
}

func (u userServiceUpdateSuccess) Update(context.Context, *types.User) (*types.User, error) {
	return &types.User{}, nil
}

func (u userServiceUpdateInvalidID) Update(context.Context, *types.User) (*types.User, error) {
	return nil, service.UserErrInvalidID()
}

func (u userServiceUpdateInvalidHandle) Update(context.Context, *types.User) (*types.User, error) {
	return nil, service.UserErrInvalidHandle()
}

func (u userServiceUpdateInvalidEmail) Update(context.Context, *types.User) (*types.User, error) {
	return nil, service.UserErrInvalidEmail()
}

func (u userServiceUpdateHandleNotUnique) Update(context.Context, *types.User) (*types.User, error) {
	return nil, service.UserErrHandleNotUnique()
}

func (u userServiceUpdateNotAllowedToUpdate) Update(context.Context, *types.User) (*types.User, error) {
	return nil, service.UserErrNotAllowedToUpdate()
}

func prepareClientRequest(ctx context.Context) *http.Request {
	return &http.Request{
		Header:   http.Header{},
		PostForm: make(url.Values),
	}
}

func prepareClientAuthService(ctx context.Context, storer store.Storer, user *types.User, memStore *memstore.MemStore) *mockAuthService {
	authService := makeMockAuthService2(ctx, storer)
	return authService
}

func prepareClientAuthHandlers(ctx context.Context, authService *mockAuthService, s *settings.Settings) *AuthHandlers {
	return &AuthHandlers{
		Log:         zap.NewNop(),
		AuthService: authService,
		Settings:    s,
	}
}

func initStore(ctx context.Context, t *testing.T) store.Storer {
	mem, err := sqlite3.ConnectInMemory(ctx)

	if err != nil {
		t.Errorf("Failed to initiate store")
	}

	return mem
}
