package criticalityscore

import (
	"context"
	"reflect"
	"testing"

	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

// 测试方法，设置模拟数据
func Test_criticalityscoreParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name      string
		doc       *processor.Document
		wantNodes []assembler.GuacNode
		wantEdges []assembler.GuacEdge
		wantErr   bool
	}{{
		name: "testing",
		doc: &processor.Document{
			Blob:              testdata.CriticalityscoreExample,
			Type:              processor.DocumentCriticalityscore,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		wantNodes: []assembler.GuacNode{
			assembler.MetadataNode{
				MetadataType: "criticalityscore",
				ID:           "github.com/kubernetes/kubernetes:4787",
				Details: map[string]interface{}{
					"repo":                    "git+https://github.com/kubernetes/kubernetes",
					"language":                "Go",
					"star_count":              100719,
					"commit_frequency":        147.31,
					"contributor_count":       4787,
					"github_mention_count":    742196,
					"issue_comment_frequency": 0.4,
					"org_count":               5,
					"recent_release_count":    72,
					"updated_issues_count":    75125,
					"score":                   8.6342,
				},
			},
			assembler.ArtifactNode{
				Name:   "git+https://github.com/kubernetes/kubernetes",
				Digest: "123",
			},
		},
		wantEdges: []assembler.GuacEdge{
			assembler.MetadataForEdge{
				MetadataNode: assembler.MetadataNode{
					MetadataType: "criticalityscore",
					ID:           "github.com/kubernetes/kubernetes:4787",
					Details: map[string]interface{}{
						"repo":                    "git+https://github.com/kubernetes/kubernetes",
						"language":                "Go",
						"star_count":              100719,
						"commit_frequency":        147.31,
						"contributor_count":       4787,
						"github_mention_count":    742196,
						"issue_comment_frequency": 0.4,
						"org_count":               5,
						"recent_release_count":    72,
						"updated_issues_count":    75125,
						"score":                   8.6342,
					},
				},
				ForArtifact: assembler.ArtifactNode{
					Name:   "git+https://github.com/kubernetes/kubernetes",
					Digest: "123",
				},
			},
		},
		wantErr: false,
	}}
	//调用方法进行测试
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewCriticalityscoreParser()
			if err := s.Parse(ctx, tt.doc); (err != nil) != tt.wantErr {
				t.Errorf("criticalityscore.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if nodes := s.CreateNodes(ctx); !reflect.DeepEqual(nodes, tt.wantNodes) {
				t.Errorf("criticalityscore.CreateNodes() = %v, want %v", nodes, tt.wantNodes)
			}
			if edges := s.CreateEdges(ctx, []assembler.IdentityNode{testdata.Ident}); !reflect.DeepEqual(edges, tt.wantEdges) {
				t.Errorf("criticalityscore.CreateEdges() = %v, want %v", edges, tt.wantEdges)
			}
		})
	}
}
