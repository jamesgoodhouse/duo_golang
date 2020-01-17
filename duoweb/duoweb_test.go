package duoweb

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"source.datanerd.us/auth-and-secrets/spam/internal/utils"
)

func TestNew(t *testing.T) {
	for _, testCase := range []struct {
		description string
	}{
		{
			description: "application key invalid",
		},
		{
			description: "integration key invalid",
		},
		{
			description: "secret key invalid",
		},
		{
			description: "time now function able to be overridden",
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
		})
	}
}

func TestSignRequest(t *testing.T) {
	for _, testCase := range []struct {
		description     string
		username        *string
		timeNowOverride *time.Time
		expected        *string
		expectedError   error
	}{
		{
			description:     "returns a signed request",
			username:        utils.StrToPtr("a username"),
			timeNowOverride: func() *time.Time { t := time.Unix(1579051550, 0); return &t }(),
			expected:        utils.StrToPtr("TX|YSB1c2VybmFtZXwwMDAwMDAwMDAwMDAwMDAwMDAwMHwxNTc5MDUxODUw|4cb154be41f943a7be697d5a0f935f3115485fe0:APP|YSB1c2VybmFtZXwwMDAwMDAwMDAwMDAwMDAwMDAwMHwxNTc5MDU1MTUw|41d5bf2eeceade27c6a2726d1180fcd9cea2f1f6"),
		},
		{
			description:   "errors when username not set",
			expectedError: errors.New("username is nil"),
		},
		{
			description:   "errors when username invalid",
			username:      utils.StrToPtr("|"),
			expectedError: errors.New("username contains invalid character '|'"),
		},
	} {
		opts := []option{}

		if testCase.timeNowOverride != nil {
			f := SetTimeNowFunc(func() time.Time { return *testCase.timeNowOverride })
			opts = append(opts, f)
		}

		d, err := New(
			"0000000000000000000000000000000000000000",
			"00000000000000000000",
			"0000000000000000000000000000000000000000",
			opts...,
		)
		if !assert.NoError(t, err) {
			assert.FailNow(t, err.Error())
		}

		t.Run(testCase.description, func(t *testing.T) {
			s, err := d.SignRequest(testCase.username)
			assert.Equal(t, testCase.expected, s)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}

func TestVerifyResponse(t *testing.T) {
	aKey := "AKEY_AKEY_AKEY_AKEY_AKEY_AKEY_AKEY_AKEY_"
	iKey := "IKEY_IKEY_IKEY_IKEY_"
	sKey := "SKEY_SKEY_SKEY_SKEY_SKEY_SKEY_SKEY_SKEY_"

	timeNow := time.Now()

	for _, testCase := range []struct {
		description      string
		authExpTime      int64
		timeNowOverride  *time.Time
		expectedError    error
		expectedUsername *string
	}{
		{
			description:      "returns a username",
			timeNowOverride:  &timeNow,
			authExpTime:      timeNow.Unix() + 1,
			expectedUsername: utils.StrToPtr("tony_the_tiger"),
		},
		{
			description:   "expired response",
			authExpTime:   timeNow.Unix() - 1,
			expectedError: errors.New("time is expired, buddy"),
		},
	} {
		opts := []option{}

		if testCase.timeNowOverride != nil {
			f := SetTimeNowFunc(func() time.Time { return *testCase.timeNowOverride })
			opts = append(opts, f)
		}

		d, err := New(aKey, iKey, sKey, opts...)
		if !assert.NoError(t, err) {
			assert.FailNow(t, err.Error())
		}

		username := "tony_the_tiger"

		authB64 := base64.StdEncoding.EncodeToString([]byte(
			fmt.Sprintf("%s|%s|%d", username, iKey, testCase.authExpTime),
		))
		h := hmac.New(sha1.New, []byte(sKey))
		h.Write([]byte("AUTH|" + authB64))
		authSig := hex.EncodeToString(h.Sum(nil))

		appB64 := base64.StdEncoding.EncodeToString([]byte(
			fmt.Sprintf("%s|%s|%d", username, iKey, timeNow.Unix()+3600),
		))
		h = hmac.New(sha1.New, []byte(aKey))
		h.Write([]byte("APP|" + appB64))
		appSig := hex.EncodeToString(h.Sum(nil))

		signedResp := fmt.Sprintf("AUTH|%s|%s:APP|%s|%s", authB64, authSig, appB64, appSig)

		t.Run(testCase.description, func(t *testing.T) {
			u, err := d.VerifyResponse(&signedResp)
			assert.Equal(t, testCase.expectedError, err)
			assert.Equal(t, testCase.expectedUsername, u)
		})
	}
}
