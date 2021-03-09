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

		req = &http.Request{PostForm: url.Values{"back": []string{"/back"}}}

		authService  *mockAuthService
		authHandlers *AuthHandlers
		authReq      *request.AuthReq
	)

	mem := initStore(ctx, t)

	authSettings := &settings.Settings{}
	service.CurrentSettings = &types.AppSettings{}
	service.CurrentSettings.Auth.Internal.Enabled = true

	authService = prepareClientAuthService(ctx, mem, user, memStore)
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
