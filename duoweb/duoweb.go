package duoweb

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"strconv"
	"strings"
	"time"
)

const (
	appPrefix  = "APP"
	authPrefix = "AUTH"
	duoPrefix  = "TX"

	appExpire = time.Duration(3600 * time.Second)
	duoExpire = time.Duration(300 * time.Second)

	aKeyLen = 40
	iKeyLen = 20
	sKeyLen = 40
)

var (
	defaultTimeNowFunc timeNowFunc = time.Now
)

type (
	Duo interface {
		SignRequest(*string) (*string, error)
		VerifyResponse(*string) (*string, error)
	}

	Config struct {
		ApplicationKey string `validate:"required,len=40"`
		IntegrationKey string `validate:"required,len=20"`
		SecretKey      string `validate:"required,len=40"`
	}

	SignRequestConfig struct {
		Username string `validate:"required,excludes=0x7C"` // 0x7C == |
		Config
	}

	timeNowFunc func() time.Time

	option func(d *duoImpl)

	duoImpl struct {
		aKey, iKey, sKey string
		timeNowFunc      timeNowFunc
	}
)

// SetTimeNowFunc ...
func SetTimeNowFunc(f timeNowFunc) option {
	return func(d *duoImpl) {
		d.timeNowFunc = f
	}
}

func New(aKey, iKey, sKey string, opts ...option) (Duo, error) {
	if len(aKey) != aKeyLen {
		return nil, errors.New("invalid application key")
	}
	if len(iKey) != iKeyLen {
		return nil, errors.New("invalid integration key")
	}
	if len(sKey) != sKeyLen {
		return nil, errors.New("invalid secret key")
	}

	d := &duoImpl{aKey, iKey, sKey, defaultTimeNowFunc}

	for _, opt := range opts {
		opt(d)
	}

	return d, nil
}

func (d duoImpl) SignRequest(username *string) (*string, error) {
	if username == nil {
		return nil, errors.New("username is nil")
	} else if strings.Contains(*username, "|") {
		return nil, errors.New("username contains invalid character '|'")
	}

	return d.signValues([]string{*username, d.iKey}), nil
}

func (d duoImpl) VerifyResponse(signedResp *string) (*string, error) {
	authSig, appSig, err := splitSignedResp(*signedResp)
	if err != nil {
		return nil, err
	}

	authUser, err := d.parseValues(d.sKey, *authSig, authPrefix, d.iKey)
	if err != nil {
		return nil, err
	}

	appUser, err := d.parseValues(d.aKey, *appSig, appPrefix, d.iKey)
	if err != nil {
		return nil, err
	}

	log.Printf("authUser: %s", *authUser)
	log.Printf("appUser: %s", *appUser)

	if *authUser != *appUser {
		return nil, errors.New("auth user not equal to app user")
	}

	return authUser, nil
}

func (d duoImpl) signValues(values []string) *string {
	duoSig := signValues(d.sKey, duoPrefix, values, duoExpire, d.timeNowFunc)
	appSig := signValues(d.aKey, appPrefix, values, appExpire, d.timeNowFunc)

	s := strings.Join([]string{duoSig, appSig}, ":")

	return &s
}

func signValues(key, prefix string, values []string, expire time.Duration, timeNow timeNowFunc) string {
	exp := timeNow().Add(expire).Unix()

	valuesWithExp := append(values, strconv.FormatInt(exp, 10))
	joinedValues := strings.Join(valuesWithExp, "|")

	b64 := base64.StdEncoding.EncodeToString([]byte(joinedValues))
	cookie := prefix + "|" + b64

	sig := hmacSHA1(key, cookie)

	return strings.Join([]string{cookie, sig}, "|")
}

func (d duoImpl) parseValues(key, val, prefix, ikey string) (*string, error) {
	tNow := d.timeNowFunc().Unix()

	uPrefix, uB64, uSig, err := splitSig(val)
	log.Printf("uPrefix: %s", *uPrefix)
	log.Printf("uB64: %s", *uB64)
	log.Printf("uSig: %s", *uSig)
	if err != nil {
		return nil, err
	}

	sig := hmacSHA1(key, *uPrefix+"|"+*uB64)
	log.Printf("sig: %s", sig)

	if hmacSHA1(key, sig) != hmacSHA1(key, *uSig) {
		return nil, errors.New("hmacSHA1 don't match")
	}

	if prefix != *uPrefix {
		return nil, errors.New("prefix don't match")
	}

	cookie, err := base64.StdEncoding.DecodeString(*uB64)
	if err != nil {
		return nil, err
	}

	user, uIKey, exp, err := splitCookie(string(cookie))
	if err != nil {
		return nil, err
	}

	if *uIKey != ikey {
		return nil, errors.New("ikeys do no match")
	}

	if tNow >= *exp {
		return nil, errors.New("time is expired, buddy")
	}

	return user, nil
}

func splitSignedResp(signedResp string) (*string, *string, error) {
	s := strings.Split(signedResp, ":")
	if len(s) != 2 {
		return nil, nil, errors.New("unable to split signed response")
	}
	return &s[0], &s[1], nil
}

func splitCookie(c string) (*string, *string, *int64, error) {
	s := strings.Split(c, "|")
	if len(s) != 3 {
		return nil, nil, nil, errors.New("problem")
	}

	ti, err := strconv.ParseInt(s[2], 10, 64)
	if err != nil {
		return nil, nil, nil, err
	}

	return &s[0], &s[1], &ti, err
}

func splitSig(sig string) (*string, *string, *string, error) {
	s := strings.Split(sig, "|")
	if len(s) != 3 {
		return nil, nil, nil, errors.New("problem")
	}
	return &s[0], &s[1], &s[2], nil
}

func hmacSHA1(key, input string) string {
	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}
