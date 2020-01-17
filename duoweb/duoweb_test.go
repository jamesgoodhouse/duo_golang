package duoweb

import (
	"errors"
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
	} {
		t.Run(testCase.description, func(t *testing.T) {
		})
	}
}

func TestSignRequest(t *testing.T) {
	for _, testCase := range []struct {
		description   string
		username      *string
		timeNowFunc   func() time.Time
		expected      *string
		expectedError error
	}{
		{
			description: "returns a signed request",
			username:    utils.StrToPtr("a username"),
			timeNowFunc: func() time.Time { return time.Unix(1579051550, 0) },
			expected:    utils.StrToPtr("TX|YSB1c2VybmFtZXwwMDAwMDAwMDAwMDAwMDAwMDAwMHwxNTc5MDUxODUw|4cb154be41f943a7be697d5a0f935f3115485fe0:APP|YSB1c2VybmFtZXwwMDAwMDAwMDAwMDAwMDAwMDAwMHwxNTc5MDU1MTUw|41d5bf2eeceade27c6a2726d1180fcd9cea2f1f6"),
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
		d, err := New(
			"0000000000000000000000000000000000000000",
			"00000000000000000000",
			"0000000000000000000000000000000000000000",
			SetTimeNowFunc(testCase.timeNowFunc),
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

// func TestVerifyResponse(t *testing.T) {
// 	for _, testCase := range []struct {
// 		description   string
// 		expectedError error
// 	}{
// 		{
// 			description: "username not set",
// 		},
// 	} {
// 		d, err := New(
// 			"0000000000000000000000000000000000000000",
// 			"00000000000000000000",
// 			"0000000000000000000000000000000000000000",
// 		)
// 		if !assert.NoError(t, err) {
// 			assert.FailNow(t, err.Error())
// 		}
// 		username := "a username"
//
// 		t.Run(testCase.description, func(t *testing.T) {
// 			_, err := d.SignRequest(&username)
// 			assert.Equal(t, testCase.expectedError, err)
// 		})
// 	}
// }
