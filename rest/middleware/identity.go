package middleware

import (
	"context"
	"log"
	"net/http"

	"github.com/RedHatInsights/chrome-service-backend/rest/service"
	"github.com/RedHatInsights/chrome-service-backend/rest/util"
	fedora_identity "github.com/osbuild/community-gateway/oidc-authorizer/pkg/identity"
)

func InjectUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fid, ok := r.Context().Value(util.IDENTITY_CTX_KEY).(*fedora_identity.Identity)
		if !ok || fid == nil {
			http.Error(w, "Fedora Identity missing in request", http.StatusUnauthorized)
			return
		}
		userId := fid.User
		if userId == "" {
			http.Error(w, "Fedora Identity does not contain a valid user", http.StatusUnauthorized)
			return
		}
		skipCache := r.URL.Query().Get("skip-identity-cache") == "true"
		userIdentity, err := service.CreateIdentity(userId, skipCache)
		if err != nil {
			log.Printf("Error creating user identity: %v", err)
			http.Error(w, "Failed to create user identity", http.StatusInternalServerError)
			return
		}
		ctx := context.WithValue(r.Context(), util.USER_CTX_KEY, userIdentity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
