//
// Copyright 2022 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scorecard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	sc "github.com/ossf/scorecard/v4/pkg"
	"github.com/spf13/viper"
)

type neo4jOptions struct {
	dbAddr  string
	user    string
	pass    string
	realm   string
	keyPath string
	keyID   string
}
type scorecardParser struct {
	scorecardNodes []assembler.MetadataNode
	// artifactNode should have a 1:1 mapping to the index
	// of scorecardNodes.
	artifactNodes []assembler.ArtifactNode
}

// 同于标识不同的工件节点name
var flag = 0

// NewScorecardParser initializes the scorecardParser
func NewScorecardParser() common.DocumentParser {
	return &scorecardParser{
		scorecardNodes: []assembler.MetadataNode{},
		artifactNodes:  []assembler.ArtifactNode{},
	}
}

// 存储scorecard
//var ScorecardDoc *sc.JSONScorecardResultV2

//var DocScorecard []*processor.Document

// Parse breaks out the document into the graph components
func (p *scorecardParser) Parse(ctx context.Context, doc *processor.Document) error {
	logger := logging.FromContext(ctx)
	if doc.Type != processor.DocumentScorecard {

		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentScorecard, doc.Type)
	}

	opts, err := validateNeo4jOps(
		viper.GetString("gdbuser"),
		viper.GetString("gdbpass"),
		viper.GetString("gdbaddr"),
		viper.GetString("realm"),
		viper.GetString("verifier-keyPath"),
		viper.GetString("verifier-keyID"),
	)
	logger.Infof("opts: %v", opts)
	if err != nil {
		fmt.Printf("unable to validate flags: %v\n", err)
	}

	switch doc.Format {
	case processor.FormatJSON:
		var scorecard sc.JSONScorecardResultV2
		if err := json.Unmarshal(doc.Blob, &scorecard); err != nil {
			return err
		}
		//修改criticalityscore的工件节点的值
		setCriticalityscoreArtifactNode(ctx, opts, &scorecard)
		p.scorecardNodes = append(p.scorecardNodes, getMetadataNode(&scorecard))
		p.artifactNodes = append(p.artifactNodes, getArtifactNode(&scorecard))

		//ScorecardDoc = &scorecard

		return nil
	}
	return fmt.Errorf("unable to support parsing of Scorecard document format: %v", doc.Format)
}

// CreateNodes creates the GuacNode for the graph inputs
func (p *scorecardParser) CreateNodes(ctx context.Context) []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	for _, n := range p.scorecardNodes {
		nodes = append(nodes, n)
	}
	for _, n := range p.artifactNodes {
		nodes = append(nodes, n)
	}

	return nodes
}

// CreateEdges creates the GuacEdges that form the relationship for the graph inputs
func (p *scorecardParser) CreateEdges(ctx context.Context, foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	// TODO: handle identity for edges (https://github.com/guacsec/guac/issues/128)
	edges := []assembler.GuacEdge{}
	for i, s := range p.scorecardNodes {
		edges = append(edges, assembler.MetadataForEdge{
			MetadataNode: s,
			ForArtifact:  p.artifactNodes[i],
		})
	}
	return edges
}

// GetIdentities gets the identity node from the document if they exist
func (p *scorecardParser) GetIdentities(ctx context.Context) []assembler.IdentityNode {
	return nil
}

func metadataId(s *sc.JSONScorecardResultV2) string {
	return fmt.Sprintf("%v:%v", s.Repo.Name, s.Repo.Commit)
}

func getMetadataNode(s *sc.JSONScorecardResultV2) assembler.MetadataNode {
	mnNode := assembler.MetadataNode{
		MetadataType: "scorecard",
		ID:           metadataId(s),
		Details:      map[string]interface{}{},
	}

	for _, c := range s.Checks {
		mnNode.Details[strings.ReplaceAll(c.Name, "-", "_")] = c.Score
	}
	mnNode.Details["repo"] = sourceUri(s.Repo.Name)
	mnNode.Details["commit"] = hashToDigest(s.Repo.Commit)
	mnNode.Details["scorecard_version"] = s.Scorecard.Version
	mnNode.Details["scorecard_commit"] = hashToDigest(s.Scorecard.Commit)
	mnNode.Details["score"] = float64(s.AggregateScore)

	return mnNode
}

func getArtifactNode(s *sc.JSONScorecardResultV2) assembler.ArtifactNode {
	return assembler.ArtifactNode{
		Name:   sourceUri(s.Repo.Name),
		Digest: hashToDigest(s.Repo.Commit),
	}
}

/*
设置criticalityscore的ArtifactNode值
*/
func setCriticalityscoreArtifactNode(ctx context.Context, opts neo4jOptions, s *sc.JSONScorecardResultV2) {

	logger := logging.FromContext(ctx)
	authToken := graphdb.CreateAuthTokenWithUsernameAndPassword(
		opts.user,
		opts.pass,
		opts.realm,
	)
	client, err := graphdb.NewGraphClient(opts.dbAddr, authToken)
	logger.Infof("驱动创建成功: %v", client)
	if err != nil {
		logger.Errorf("驱动创建失败")
		return
	}
	// 创建一个会话
	session := client.NewSession(neo4j.SessionConfig{})
	logger.Infof("会话创建成功: %v", session)
	defer session.Close()

	// 开始一个事务
	tx, err := session.BeginTransaction()
	if err != nil {
		fmt.Println("Failed to begin transaction: ", err)
		return
	}

	// 执行 Cypher 查询并修改数据
	result, err := tx.Run("MATCH (n:Artifact {name: $name}) SET n.digest = $digest", map[string]interface{}{
		"name":   sourceUri(s.Repo.Name) + ":" + strconv.Itoa(flag),
		"digest": hashToDigest(s.Repo.Commit),
	})
	//执行一次修改让flag加1，标识不同的name
	flag = flag + 1
	logger.Infof("flag:", flag)
	logger.Infof("修改数据成功:", result)
	if err != nil {
		logger.Errorf("修改数据失败:", err)
		return
	}

	// 检查是否有错误
	if err = result.Err(); err != nil {
		logger.Errorf("Query execution failed: ", err)
		return
	}
	// 提交事务
	err = tx.Commit()
	if err != nil {
		fmt.Println("Failed to commit transaction: ", err)
		return
	}
}
func validateNeo4jOps(user string, pass string, dbAddr string, realm string, keyPath string, keyID string) (neo4jOptions, error) {
	var opts neo4jOptions
	opts.user = user
	opts.pass = pass
	opts.dbAddr = dbAddr
	opts.realm = realm

	if keyPath != "" {
		if strings.HasSuffix(keyPath, "pem") {
			opts.keyPath = keyPath
		} else {
			return opts, errors.New("key must be passed in as a pem file")
		}
	}
	if keyPath != "" {
		opts.keyID = keyID
	}
	return opts, nil
}
func sourceUri(s string) string {
	return "git+https://" + s
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

func (p *scorecardParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return nil, fmt.Errorf("not yet implemented")
}
