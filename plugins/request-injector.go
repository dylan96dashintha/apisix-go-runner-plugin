package plugins

import (
	"encoding/json"
	"fmt"
	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/apache/apisix-go-plugin-runner/pkg/log"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
)

type RequestInjectorPlugin struct {
}

type RequestInjectorConfig struct {
	ValidAzpList []string `json:"valid_azp_list"`
	SecretKey    string   `json:"secret_key"`
}

func (re *RequestInjectorPlugin) Name() string {
	return "go-plugin-request-injector"
}

func (re *RequestInjectorPlugin) ParseConf(in []byte) (interface{}, error) {
	conf := RequestInjectorConfig{}
	err := json.Unmarshal(in, &conf)
	if err != nil {
		log.Errorf("error in unmarshalling err: %s", err)
		return nil, err
	}
	return conf, err
}

func (re *RequestInjectorPlugin) RequestFilter(conf interface{}, w http.ResponseWriter, r pkgHTTP.Request) {
	config, _ := conf.(RequestInjectorConfig)
	authHeader := r.Header().Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header missing", http.StatusUnauthorized)
		return
	}

	// Expecting header in format "Bearer <token>"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	tokenString := parts[1]
	log.Infof("token string, token:", tokenString)

	// Parse and validate the JWT
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Make sure token algorithm matches expected
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Errorf("not ok : ", ok)
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		log.Infof("secret :", config.SecretKey)
		return []byte(config.SecretKey), nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Access claims if needed
	var (
		azp    string
		userId string
	)
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		for k, v := range claims {
			if k == "iss" {
				log.Infof("iss :", v)
				azp = v.(string)
			}

			if k == "userId" {
				log.Infof("userId :", v)
				userId = v.(string)
			}
		}
	} else {
		http.Error(w, "Could not parse claims", http.StatusInternalServerError)
	}

	if !validateAzp(azp, config.ValidAzpList) {
		http.Error(w, "Unauthorized azp", http.StatusUnauthorized)
	}
	r.Header().Set("X-User-Id", userId)

}

func validateAzp(azp string, validAzpList []string) bool {
	for _, validAzp := range validAzpList {
		if validAzp == azp {
			return true
		}
	}
	return false
}

func (re *RequestInjectorPlugin) ResponseFilter(conf interface{}, w pkgHTTP.Response) {
	//TODO implement me
	panic("implement me")
}
