package criticalityscore

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	cs "github.com/guacsec/guac/pkg/handler/processor/criticalityscore"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
)

type criticalityscoreParser struct {
	criticalityscoreNodes []assembler.MetadataNode
	// artifactNode should have a 1:1 mapping to the index
	// of criticalityscoreNodes.
	artifactNodes []assembler.ArtifactNode
}

// NewCriticalityscoreParser initializes the criticalityscoreParser
func NewCriticalityscoreParser() common.DocumentParser {
	return &criticalityscoreParser{
		criticalityscoreNodes: []assembler.MetadataNode{},
		artifactNodes:         []assembler.ArtifactNode{},
	}
}

// 接收scorecard字节数据

// Parse breaks out the document into the graph components
// Parse方法将文档分解为图形组件
func (p *criticalityscoreParser) Parse(ctx context.Context, doc *processor.Document) error {

	if doc.Type != processor.DocumentCriticalityscore {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentCriticalityscore, doc.Type)
	}

	//logger.Infof("s1 的文档数组为: %v", s1)
	switch doc.Format {
	case processor.FormatJSON:
		var criticalityscore cs.JSONCriticalityScoreResult
		if err := json.Unmarshal(doc.Blob, &criticalityscore); err != nil {
			return err
		}

		//生成不同的criticalityscore的父节点，用i来标识
		for i := 0; i < getScorecardDocsNum(ctx); i++ {
			p.criticalityscoreNodes = append(p.criticalityscoreNodes, getMetadataNode(i, &criticalityscore))
			p.artifactNodes = append(p.artifactNodes, getArtifactNode(i, &criticalityscore))
		}

		//logger.Infof("Criticalityscoreparser为: %v", Criticalityscoreparser)
		return nil
	}
	return fmt.Errorf("unable to support parsing of Criticalityscore document format: %v", doc.Format)
}

// CreateNodes creates the GuacNode for the graph inputs
func (p *criticalityscoreParser) CreateNodes(ctx context.Context) []assembler.GuacNode {
	logger := logging.FromContext(ctx)
	nodes := []assembler.GuacNode{}
	for _, n := range p.criticalityscoreNodes {
		nodes = append(nodes, n)
	}
	for _, n := range p.artifactNodes {
		nodes = append(nodes, n)
	}

	logger.Infof("Criticalitynodes为: %v", nodes)
	return nodes
}

// CreateEdges creates the GuacEdges that form the relationship for the graph inputs
func (p *criticalityscoreParser) CreateEdges(ctx context.Context, foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {

	edges := []assembler.GuacEdge{}
	for i, s := range p.criticalityscoreNodes {
		edges = append(edges, assembler.MetadataForEdge{
			MetadataNode: s,
			ForArtifact:  p.artifactNodes[i],
		})
	}
	return edges
}

// GetIdentities gets the identity node from the document if they exist
func (p *criticalityscoreParser) GetIdentities(ctx context.Context) []assembler.IdentityNode {
	return nil
}

// 构建元数据ID
func metadataId(flag int, s *cs.JSONCriticalityScoreResult) string {
	return fmt.Sprintf("%v:%v", s.Repo.URL[len("https://"):len(s.Repo.URL)], strconv.Itoa(flag))
}

// 构建元数据节点
func getMetadataNode(flag int, s *cs.JSONCriticalityScoreResult) assembler.MetadataNode {
	mnNode := assembler.MetadataNode{
		MetadataType: "criticalityscore",
		ID:           metadataId(flag, s),
		Details:      map[string]interface{}{},
	}
	//转换数据结果类型为float
	score, _ := strconv.ParseFloat(s.DefaultScore, 64)
	//设置数据
	mnNode.Details["repo"] = sourceUri(s.Repo.URL)
	mnNode.Details["language"] = s.Repo.Language
	mnNode.Details["star_count"] = s.Repo.StarCount
	mnNode.Details["commit_frequency"] = s.Legacy.CommitFrequency
	mnNode.Details["contributor_count"] = s.Legacy.ContributorCount
	mnNode.Details["github_mention_count"] = s.Legacy.GithubMentionCount
	mnNode.Details["issue_comment_frequency"] = s.Legacy.IssueCommentFrequency
	mnNode.Details["recent_release_count"] = s.Legacy.RecentReleaseCount
	mnNode.Details["org_count"] = s.Legacy.OrgCount
	mnNode.Details["updated_issues_count"] = s.Legacy.UpdatedIssuesCount
	mnNode.Details["closed_issues_count"] = s.Legacy.ClosedIssuesCount
	// mnNode.Details["created_since"] = s.Legacy.CreatedSince
	// mnNode.Details["updated_since"] = s.Legacy.UpdatedSince
	// mnNode.Details["created_at"] = s.Repo.CreatedAt
	// mnNode.Details["updated_at"] = s.Repo.UpdatedAt
	mnNode.Details["score"] = score * 10

	return mnNode
}

// 获取工件节点
func getArtifactNode(flag int, c *cs.JSONCriticalityScoreResult) assembler.ArtifactNode {
	return assembler.ArtifactNode{
		Name:   sourceUri(c.Repo.URL) + ":" + strconv.Itoa(flag),
		Digest: strconv.Itoa(flag),
	}
}

// 设置uri
func sourceUri(s string) string {
	return "git+" + s
}

func hashToDigest(h string) string {
	switch len(h) {
	case 40:
		return "sha1:" + h
	case 64:
		return "sha256:" + h
	case 128:
		return "sha512:" + h
	}
	return h
}

// 获取识别器
func (p *criticalityscoreParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return nil, fmt.Errorf("not yet implemented")
}
