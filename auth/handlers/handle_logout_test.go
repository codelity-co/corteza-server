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

// @todo - fix the rq.NotEmpty(authReq.Session.Values)
func Test_logoutProc(t *testing.T) {
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

	service.CurrentSettings = &types.AppSettings{}
	service.CurrentSettings.Auth.Internal.Enabled = true

	authService = makeMockAuthService(ctx)
	req.PostForm.Add("back", "/back")

	h := AuthHandlers{
		Log:         zap.NewNop(),
		AuthService: authService,
	}

	sess := sessions.NewSession(memStore, "session")
	sess.Values = map[interface{}]interface{}{"key": url.Values{"key": []string{"value"}}}

	authReq := request.AuthReq{
		Request:  req,
		User:     user,
		Session:  sess,
		Response: httptest.NewRecorder(),
		Data:     make(map[string]interface{}),
	}

	err := h.logoutProc(&authReq)

	rq.NoError(err)
	rq.NotEmpty(authReq.Session.Values)
	rq.Empty(authReq.User)
	rq.Empty(authReq.Client)
	rq.Equal("/back", authReq.Data["backlink"])
	rq.Equal(TmplLogout, authReq.Template)
}
