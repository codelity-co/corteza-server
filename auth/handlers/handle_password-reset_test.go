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

func Test_requestPasswordResetProc(t *testing.T) {
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
		User:     userReq,
		Session:  sessions.NewSession(memStore, "session"),
		Response: httptest.NewRecorder(),
		Data:     make(map[string]interface{}),
	}

	err := h.requestPasswordResetProc(&authReq)

	rq.NoError(err)
	rq.Equal(GetLinks().PasswordResetRequested, authReq.RedirectTo)
}
