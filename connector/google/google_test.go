package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

var (
	// groups_0
	//		├─────────────────┐
	//	groups_1 			user_3
	//		├──────────┐
	//	user_1		 user_2
	testGroups = map[string]admin.Groups{
		"user_1@dexidp.com":   {Groups: []*admin.Group{{Email: "groups_1@dexidp.com"}}},
		"user_2@dexidp.com":   {Groups: []*admin.Group{{Email: "groups_1@dexidp.com"}}},
		"groups_1@dexidp.com": {Groups: []*admin.Group{{Email: "groups_0@dexidp.com"}}},
		"user_3@dexidp.com":   {Groups: []*admin.Group{{Email: "groups_0@dexidp.com"}}},
		"groups_0@dexidp.com": {Groups: []*admin.Group{}},
	}
)

func testSetup(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/admin/directory/v1/groups/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		userKey := r.URL.Query().Get("userKey")
		if groups, ok := testGroups[userKey]; ok {
			json.NewEncoder(w).Encode(groups)
		}
	})

	return httptest.NewServer(mux)
}

func newConnector(config *Config, serverURL string) (*googleConnector, error) {
	log := logrus.New()
	conn, err := config.Open("id", log)
	if err != nil {
		return nil, err
	}

	googleConn, ok := conn.(*googleConnector)
	if !ok {
		return nil, fmt.Errorf("failed to convert to googleConnector")
	}
	return googleConn, nil
}

func tempServiceAccountKey() (string, error) {
	fd, err := os.CreateTemp("", "google_service_account_key")
	if err != nil {
		return "", err
	}
	defer fd.Close()
	err = json.NewEncoder(fd).Encode(map[string]string{
		"type":                 "service_account",
		"project_id":           "sample-project",
		"private_key_id":       "sample-key-id",
		"private_key":          "-----BEGIN PRIVATE KEY-----\nsample-key\n-----END PRIVATE KEY-----\n",
		"client_id":            "sample-client-id",
		"client_x509_cert_url": "localhost",
	})
	return fd.Name(), err
}

func TestOpen(t *testing.T) {
	ts := testSetup(t)
	defer ts.Close()

	type testCase struct {
		config      *Config
		expectedErr string

		// string to set in GOOGLE_APPLICATION_CREDENTIALS. As local development environments can
		// already contain ADC, test cases will be built uppon this setting this env variable
		adc string
	}

	serviceAccountFilePath, err := tempServiceAccountKey()
	assert.Nil(t, err)

	for name, reference := range map[string]testCase{
		"missing_admin_email": {
			config: &Config{
				ClientID:     "testClient",
				ClientSecret: "testSecret",
				RedirectURI:  ts.URL + "/callback",
				Scopes:       []string{"openid", "groups"},
			},
			expectedErr: "requires adminEmail",
		},
		"service_account_key_not_found": {
			config: &Config{
				ClientID:               "testClient",
				ClientSecret:           "testSecret",
				RedirectURI:            ts.URL + "/callback",
				Scopes:                 []string{"openid", "groups"},
				AdminEmail:             "foo@bar.com",
				ServiceAccountFilePath: "not_found.json",
			},
			expectedErr: "error reading credentials",
		},
		"service_account_key_valid": {
			config: &Config{
				ClientID:               "testClient",
				ClientSecret:           "testSecret",
				RedirectURI:            ts.URL + "/callback",
				Scopes:                 []string{"openid", "groups"},
				AdminEmail:             "foo@bar.com",
				ServiceAccountFilePath: serviceAccountFilePath,
			},
			expectedErr: "",
		},
		"adc": {
			config: &Config{
				ClientID:     "testClient",
				ClientSecret: "testSecret",
				RedirectURI:  ts.URL + "/callback",
				Scopes:       []string{"openid", "groups"},
				AdminEmail:   "foo@bar.com",
			},
			adc:         serviceAccountFilePath,
			expectedErr: "",
		},
		"adc_priority": {
			config: &Config{
				ClientID:               "testClient",
				ClientSecret:           "testSecret",
				RedirectURI:            ts.URL + "/callback",
				Scopes:                 []string{"openid", "groups"},
				AdminEmail:             "foo@bar.com",
				ServiceAccountFilePath: serviceAccountFilePath,
			},
			adc:         "/dev/null",
			expectedErr: "",
		},
	} {
		reference := reference
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", reference.adc)
			conn, err := newConnector(reference.config, ts.URL)

			if reference.expectedErr == "" {
				assert.Nil(err)
				assert.NotNil(conn)
			} else {
				assert.ErrorContains(err, reference.expectedErr)
			}
		})
	}
}

func TestUniqueInsert(t *testing.T) {
	type testCase struct {
		target   []string
		insert   []string
		expected []string
	}

	for name, testCase := range map[string]testCase{
		"unique_insert": {
			target:   []string{"group_0"},
			insert:   []string{"group_1"},
			expected: []string{"group_0", "group_1"},
		},
		"non_unique_insert": {
			target:   []string{"group_0"},
			insert:   []string{"group_0"},
			expected: []string{"group_0"},
		},
		"empty_insert": {
			target:   []string{"group_0"},
			insert:   []string{},
			expected: []string{"group_0"},
		},
	} {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			assert.Equal(testCase.expected, uniqueInsert(testCase.target, testCase.insert...))
		})
	}
}

func TestGetGroups(t *testing.T) {
	ts := testSetup(t)
	defer ts.Close()

	serviceAccountFilePath, err := tempServiceAccountKey()
	assert.Nil(t, err)

	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", serviceAccountFilePath)
	conn, err := newConnector(&Config{
		ClientID:     "testClient",
		ClientSecret: "testSecret",
		RedirectURI:  ts.URL + "/callback",
		Scopes:       []string{"openid", "groups"},
		AdminEmail:   "admin@dexidp.com",
	}, ts.URL)
	assert.Nil(t, err)

	conn.adminSrv, err = admin.NewService(context.Background(), option.WithoutAuthentication(), option.WithEndpoint(ts.URL))
	assert.Nil(t, err)

	type testCase struct {
		userKey                        string
		fetchTransitiveGroupMembership bool
		shouldErr                      bool
		expectedGroups                 []string
	}

	for name, testCase := range map[string]testCase{
		"user1_non_transitive_lookup": {
			userKey:                        "user_1@dexidp.com",
			fetchTransitiveGroupMembership: false,
			shouldErr:                      false,
			expectedGroups:                 []string{"groups_1@dexidp.com"},
		},
		"user1_transitive_lookup": {
			userKey:                        "user_1@dexidp.com",
			fetchTransitiveGroupMembership: true,
			shouldErr:                      false,
			expectedGroups:                 []string{"groups_1@dexidp.com", "groups_0@dexidp.com"},
		},
	} {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			lookup := make(map[string]struct{})

			groups, err := conn.getGroups(testCase.userKey, testCase.fetchTransitiveGroupMembership, lookup)
			if testCase.shouldErr {
				assert.NotNil(err)
			} else {
				assert.Nil(err)
			}
			assert.ElementsMatch(testCase.expectedGroups, groups)
		})
	}
}
