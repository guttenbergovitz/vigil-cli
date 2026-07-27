package types

// DependencyNode represents a single package in the dependency tree.
type DependencyNode struct {
	Name            string
	Version         string
	Ecosystem       Ecosystem       // Package ecosystem (npm, PyPI, Go, Cargo, etc.)
	Type            DependencyType  // production or development
	Direct          bool            // whether direct dependency or transitive
	Depth           int             // 0 = direct, 1 = dependency of direct, etc.
	Parents         []string        // slice of "name@version" which depend on this
	Children        []string        // slice of "name@version" this depends on
	Vulnerabilities []Vulnerability // CVEs for this package
}

// DependencyGraph represents a full dependency tree.
type DependencyGraph struct {
	Ecosystem Ecosystem                   // Overall ecosystem of graph
	Nodes     map[string]*DependencyNode // key: "name@version"
	Root      []string                   // direct dependencies: []"name@version"
}

// NewDependencyGraph creates a new empty graph.
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		Ecosystem: EcosystemNPM,
		Nodes:     make(map[string]*DependencyNode),
		Root:      make([]string, 0),
	}
}

// AddNode adds a node to the graph.
func (g *DependencyGraph) AddNode(name, version string, typ DependencyType, direct bool) *DependencyNode {
	key := name + "@" + version
	if node, exists := g.Nodes[key]; exists {
		return node
	}

	node := &DependencyNode{
		Name:      name,
		Version:   version,
		Ecosystem: g.Ecosystem,
		Type:      typ,
		Direct:    direct,
		Depth:     -1,
		Parents:   make([]string, 0),
		Children:  make([]string, 0),
	}

	g.Nodes[key] = node
	return node
}

// AddEdge dodaje relację parent -> child.
func (g *DependencyGraph) AddEdge(parentKey, childKey string) {
	if parent, exists := g.Nodes[parentKey]; exists {
		parent.Children = append(parent.Children, childKey)
	}
	if child, exists := g.Nodes[childKey]; exists {
		child.Parents = append(child.Parents, parentKey)
	}
}

// CalculateDepths oblicza depth każdego node'a (BFS).
func (g *DependencyGraph) CalculateDepths() {
	// Reset depths
	for _, node := range g.Nodes {
		node.Depth = -1
	}

	// BFS starting from roots
	queue := make([]string, len(g.Root))
	copy(queue, g.Root)

	for _, key := range queue {
		if node, exists := g.Nodes[key]; exists {
			node.Depth = 0
		}
	}

	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]

		if node, exists := g.Nodes[key]; exists {
			for _, childKey := range node.Children {
				if child, childExists := g.Nodes[childKey]; childExists {
					if child.Depth < 0 || child.Depth > node.Depth+1 {
						child.Depth = node.Depth + 1
						queue = append(queue, childKey)
					}
				}
			}
		}
	}
}

// GetVulnerablePath zwraca ścieżkę od root do vulnerable node'a.
func (g *DependencyGraph) GetVulnerablePath(nodeKey string) []string {
	path := []string{nodeKey}
	node, exists := g.Nodes[nodeKey]
	if !exists {
		return path
	}

	// Walk backwards through parents until reaching a root
	current := nodeKey
	visited := make(map[string]bool)

	for len(node.Parents) > 0 && !visited[current] {
		visited[current] = true
		// Take first parent (could be multiple)
		parentKey := node.Parents[0]
		path = append([]string{parentKey}, path...)

		if parent, exists := g.Nodes[parentKey]; exists {
			node = parent
			current = parentKey
		} else {
			break
		}
	}

	return path
}
