package handlers

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/cortezaproject/corteza-server/auth/request"
	"github.com/cortezaproject/corteza-server/auth/settings"
	"github.com/cortezaproject/corteza-server/system/service"
	"github.com/cortezaproject/corteza-server/system/types"
	"github.com/quasoft/memstore"
	"github.com/stretchr/testify/require"
)

func Test_mfaProc(t *testing.T) {
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

		tcc = []testingExpect{
			{
				name:    "successful login",
				payload: map[string]string(nil),
				alerts:  []request.Alert{{Type: "primary", Text: "Email OTP valid"}},
				link:    GetLinks().Profile,
				fn: func() {
					req.Form.Set("action", "verifyEmailOtp")
					service.CurrentSettings.Auth.Internal.Enabled = true
					req.PostForm.Add("code", "CODE_HERE")
				},
			},
		}
	)

	mem := initStore(ctx, t)

	service.CurrentSettings = &types.AppSettings{}

	for _, tc := range tcc {
		t.Run(tc.name, func(t *testing.T) {
			// reset from previous
			req.PostForm = url.Values{}
			req.Form = url.Values{}

			tc.fn()

			authService = prepareClientAuthService(ctx, mem, user, memStore)
			authReq = prepareClientAuthReq(ctx, req, user, memStore)
			authHandlers = prepareClientAuthHandlers(ctx, authService, authSettings)

			authHandlers.UserService = tc.userService
			authService.store.TruncateUsers(ctx)
			authService.store.CreateUser(ctx, user)
			authService.SetPassword(ctx, user.ID, "an_old_password_of_mine")

			err := authHandlers.mfaProc(authReq)

			rq.NoError(err)
			// rq.Equal(tc.payload, authReq.GetKV())
			rq.Equal(tc.alerts, authReq.NewAlerts)
			// rq.Equal(tc.link, authReq.RedirectTo)
		})
	}
}
