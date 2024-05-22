package http_client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"
)

func GetJson(apiUrl, proxyUrl string, headers map[string]string) ([]byte, error) {
	var err error

	var client *http.Client
	var tr *http.Transport

	tr = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 60 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 60 * time.Second,

		ExpectContinueTimeout: 60 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}

	if proxyUrl != "" {
		proxy, _ := url.Parse(proxyUrl)
		tr.Proxy = http.ProxyURL(proxy)
	}

	client = &http.Client{
		Transport: tr,
	}

	//read body string
	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return nil, err
	}

	if headers != nil {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}

	// timeout in 10 mins
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	nReq := req.WithContext(ctx)
	resp, err := client.Do(nReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("%s", resp.Status)
	}

	// Retrieve the body of the response
	out, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return out, err
}

func PostJson(apiUrl, proxyUrl string, jsonBody []byte) ([]byte, error) {
	var err error

	var client *http.Client
	var tr *http.Transport

	tr = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 60 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 60 * time.Second,

		ExpectContinueTimeout: 60 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}

	if proxyUrl != "" {
		proxy, _ := url.Parse(proxyUrl)
		tr.Proxy = http.ProxyURL(proxy)
	}

	client = &http.Client{
		Transport: tr,
	}

	reader := bytes.NewReader(jsonBody)
	//read body string
	req, err := http.NewRequest("POST", apiUrl, reader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	// timeout in 10 mins
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	nReq := req.WithContext(ctx)
	resp, err := client.Do(nReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("%s", resp.Status)
	}

	// Retrieve the body of the response
	out, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return out, err
}
