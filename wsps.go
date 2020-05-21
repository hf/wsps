package wsps

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type Request struct {
	Method             string
	Region             string
	Host               string
	Stage              string
	ConnectionId       string
	BodySha256         []byte
	Date               time.Time
	ExpiresInSeconds   uint
	AWSAccessKeyId     string
	AWSSecretAccessKey string
	AWSSecurityToken   string
}

type PreSignedRequest struct {
	URL              string
	CanonicalRequest string
	StringToSign     string
}

func PreSign(request Request) PreSignedRequest {
	var result PreSignedRequest

	date := request.Date.UTC().Format("20060102T150405Z")
	coarseDate := string(date[0:8])
	expires := fmt.Sprintf("%d", request.ExpiresInSeconds)

	qs := strings.Join([]string{
		"X-Amz-Algorithm=AWS4-HMAC-SHA256",
		"X-Amz-Credential=" + url.QueryEscape(
			strings.Join([]string{
				request.AWSAccessKeyId,
				coarseDate,
				request.Region,
				"execute-api",
				"aws4_request",
			}, "/")),
		"X-Amz-Date=" + date,
		"X-Amz-Expires=" + expires,
		"X-Amz-Security-Token=" + url.QueryEscape(request.AWSSecurityToken),
		"X-Amz-SignedHeaders=" + url.QueryEscape("host"),
	}, "&")

	req := strings.Join([]string{
		request.Method,
		strings.Join([]string{
			"",
			url.QueryEscape(request.Stage),
			url.QueryEscape("@connections"),
			url.QueryEscape(request.ConnectionId),
		}, "/"),
		qs,
		"host:" + request.Host + "\n",
		"host",
		hex.EncodeToString(request.BodySha256),
	}, "\n")
	result.CanonicalRequest = req

	hash := sha256.New()
	hash.Write([]byte(req))

	sts := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		date,
		strings.Join([]string{
			coarseDate,
			request.Region,
			"execute-api",
			"aws4_request",
		}, "/"),
		hex.EncodeToString(hash.Sum(nil)),
	}, "\n")
	result.StringToSign = sts

	mac := hmac.New(sha256.New, []byte("AWS4"+request.AWSSecretAccessKey))
	mac.Write([]byte(coarseDate))
	mac = hmac.New(sha256.New, mac.Sum(nil))
	mac.Write([]byte(request.Region))
	mac = hmac.New(sha256.New, mac.Sum(nil))
	mac.Write([]byte("execute-api"))
	mac = hmac.New(sha256.New, mac.Sum(nil))
	mac.Write([]byte("aws4_request"))

	mac = hmac.New(sha256.New, mac.Sum(nil))
	mac.Write([]byte(sts))
	signature := hex.EncodeToString(mac.Sum(nil))

	url := strings.Join([]string{
		"https:/",
		request.Host,
		request.Stage,
		"@connections",
		request.ConnectionId,
	}, "/") + "?" + qs + "&X-Amz-Signature=" + signature
	result.URL = url

	return result
}
