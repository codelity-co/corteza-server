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

func Test_logoutProc(t *testing.T) {
	var (
		ctx      = context.Background()
		memStore = memstore.NewMemStore()
		rq       = require.New(t)
		user     = makeMockUser(ctx)

		req = &http.Request{
			Header:   http.Header{},
			PostForm: make(url.Values),
		}

		authService  *mockAuthService
		authHandlers *AuthHandlers
		authReq      *request.AuthReq
	)

	mem := initStore(ctx, t)

	service.CurrentSettings = &types.AppSettings{}
	service.CurrentSettings.Auth.Internal.Enabled = true

	authSettings := &settings.Settings{}

	authService = prepareClientAuthService(ctx, mem, user, memStore)
	req.PostForm.Add("back", "/back")

	authReq = prepareClientAuthReq(ctx, req, user, memStore)
	authHandlers = prepareClientAuthHandlers(ctx, authService, authSettings)

	authReq.Session.Values = map[interface{}]interface{}{"key": url.Values{"key": []string{"value"}}}

	err := authHandlers.logoutProc(authReq)

	rq.NoError(err)
	rq.Empty(authReq.Session.Values)
	rq.Empty(authReq.AuthUser)
	rq.Empty(authReq.Client)
	rq.Equal("/back", authReq.Data["backlink"])
	rq.Equal(TmplLogout, authReq.Template)
}
