package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.24

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// CertifyVuln is the resolver for the CertifyVuln field.
func (r *queryResolver) CertifyVuln(ctx context.Context, certifyVulnSpec *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {
	return r.Backend.CertifyVuln(ctx, certifyVulnSpec)
}
