package handlers

import (
	"context"

	"github.com/cortezaproject/corteza-server/auth/request"
	"github.com/cortezaproject/corteza-server/system/types"
	"github.com/markbates/goth"
)

type (
	testingExpect struct {
		name        string
		payload     interface{}
		link        string
		err         string
		template    string
		alerts      []request.Alert
		userService userService
		fn          func()
	}

	userServiceMocked struct {
		update func(context.Context, *types.User) (*types.User, error)
	}

	authServiceMocked struct {
		external                          func(context.Context, goth.User) (u *types.User, err error)
		internalSignUp                    func(context.Context, *types.User, string) (u *types.User, err error)
		internalLogin                     func(context.Context, string, string) (u *types.User, err error)
		setPassword                       func(context.Context, uint64, string) (err error)
		changePassword                    func(context.Context, uint64, string, string) (err error)
		validateEmailConfirmationToken    func(context.Context, string) (user *types.User, err error)
		validatePasswordResetToken        func(context.Context, string) (user *types.User, err error)
		sendEmailAddressConfirmationToken func(context.Context, *types.User) (err error)
		sendPasswordResetToken            func(context.Context, string) (err error)
		getProviders                      func() types.ExternalAuthProviderSet
		validateTOTP                      func(context.Context, string) (err error)
		configureTOTP                     func(context.Context, string, string) (u *types.User, err error)
		removeTOTP                        func(context.Context, uint64, string) (u *types.User, err error)
		sendEmailOTP                      func(context.Context) (err error)
		configureEmailOTP                 func(context.Context, uint64, bool) (u *types.User, err error)
		validateEmailOTP                  func(context.Context, string) (err error)
	}
)

func (u userServiceMocked) Update(ctx context.Context, user *types.User) (*types.User, error) {
	return u.update(ctx, user)
}

func (s authServiceMocked) External(ctx context.Context, profile goth.User) (u *types.User, err error) {
	return s.external(ctx, profile)
}

func (s authServiceMocked) InternalSignUp(ctx context.Context, input *types.User, password string) (u *types.User, err error) {
	return s.internalSignUp(ctx, input, password)
}

func (s authServiceMocked) InternalLogin(ctx context.Context, email string, password string) (u *types.User, err error) {
	return s.internalLogin(ctx, email, password)
}

func (s authServiceMocked) SetPassword(ctx context.Context, userID uint64, password string) (err error) {
	return s.setPassword(ctx, userID, password)
}

func (s authServiceMocked) ChangePassword(ctx context.Context, userID uint64, oldPassword, newPassword string) (err error) {
	return s.changePassword(ctx, userID, oldPassword, newPassword)
}

func (s authServiceMocked) ValidateEmailConfirmationToken(ctx context.Context, token string) (user *types.User, err error) {
	return s.validateEmailConfirmationToken(ctx, token)
}

func (s authServiceMocked) ValidatePasswordResetToken(ctx context.Context, token string) (user *types.User, err error) {
	return s.validatePasswordResetToken(ctx, token)
}

func (s authServiceMocked) SendEmailAddressConfirmationToken(ctx context.Context, u *types.User) (err error) {
	return s.sendEmailAddressConfirmationToken(ctx, u)
}

func (s authServiceMocked) SendPasswordResetToken(ctx context.Context, email string) (err error) {
	return s.sendPasswordResetToken(ctx, email)
}

func (s authServiceMocked) GetProviders() types.ExternalAuthProviderSet {
	return s.getProviders()
}

func (s authServiceMocked) ValidateTOTP(ctx context.Context, code string) (err error) {
	return s.validateTOTP(ctx, code)
}

func (s authServiceMocked) ConfigureTOTP(ctx context.Context, secret string, code string) (u *types.User, err error) {
	return s.configureTOTP(ctx, secret, code)
}

func (s authServiceMocked) RemoveTOTP(ctx context.Context, userID uint64, code string) (u *types.User, err error) {
	return s.removeTOTP(ctx, userID, code)
}

func (s authServiceMocked) SendEmailOTP(ctx context.Context) (err error) {
	return s.sendEmailOTP(ctx)
}

func (s authServiceMocked) ConfigureEmailOTP(ctx context.Context, userID uint64, enable bool) (u *types.User, err error) {
	return s.configureEmailOTP(ctx, userID, enable)
}

func (s authServiceMocked) ValidateEmailOTP(ctx context.Context, code string) (err error) {
	return s.validateEmailOTP(ctx, code)
}
