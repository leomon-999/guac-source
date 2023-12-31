package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.24

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// CertifyPkg is the resolver for the CertifyPkg field.
func (r *queryResolver) CertifyPkg(ctx context.Context, certifyPkgSpec *model.CertifyPkgSpec) ([]*model.CertifyPkg, error) {
	return r.Backend.CertifyPkg(ctx, certifyPkgSpec)
}
