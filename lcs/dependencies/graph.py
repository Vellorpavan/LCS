"""
LCS Dependency Graph & Cycle Detection (Phase 2B)
=================================================
Implements directed dependency graph construction, Tarjan/DFS cycle detection,
missing dependency validation, and deterministic topological resolution.
"""

from typing import Dict, Any, List, Set, Optional, Tuple
from .models import ResourceType, DependencyType, DependencyNode, DependencyEdge


class DependencyError(Exception):
    """Base exception for dependency resolution failures."""
    pass


class CircularDependencyError(DependencyError):
    """Raised when a circular reference is detected in the dependency graph."""
    def __init__(self, cycle_path: List[str]):
        self.cycle_path = cycle_path
        formatted = " -> ".join(cycle_path)
        super().__init__(f"Circular dependency cycle detected: {formatted}")


class MissingDependencyError(DependencyError):
    """Raised when a mandatory dependency cannot be satisfied."""
    def __init__(self, missing_edges: List[DependencyEdge]):
        self.missing_edges = missing_edges
        details = ", ".join(f"{e.dependent_id} requires {e.depends_on_id}" for e in missing_edges)
        super().__init__(f"Missing mandatory dependencies: {details}")


class DependencyGraph:
    """
    Directed graph representing resource dependencies.
    Directs edges from dependent to dependency: A -> B means 'A depends on B'.
    Execution order requires B to be prepared/executed before A.
    """

    def __init__(self):
        self.nodes: Dict[str, DependencyNode] = {}
        self.adjacency: Dict[str, Set[str]] = {}        # node -> set of nodes it depends on
        self.reverse_adjacency: Dict[str, Set[str]] = {}# node -> set of nodes that depend on it
        self.edges: List[DependencyEdge] = []

    def add_node(self, node: DependencyNode) -> None:
        """Adds a resource node to the graph."""
        if node.resource_id not in self.nodes:
            self.nodes[node.resource_id] = node
            self.adjacency[node.resource_id] = set()
            self.reverse_adjacency[node.resource_id] = set()

    def add_dependency(
        self,
        dependent_id: str,
        depends_on_id: str,
        dependency_type: DependencyType = DependencyType.MANDATORY,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Adds a directed dependency edge: dependent_id depends on depends_on_id.
        """
        if dependent_id not in self.nodes:
            self.nodes[dependent_id] = DependencyNode(
                resource_id=dependent_id,
                resource_type=ResourceType.SKILL
            )
            self.adjacency[dependent_id] = set()
            self.reverse_adjacency[dependent_id] = set()

        if depends_on_id not in self.adjacency:
            self.adjacency[depends_on_id] = set()
        if depends_on_id not in self.reverse_adjacency:
            self.reverse_adjacency[depends_on_id] = set()

        self.adjacency[dependent_id].add(depends_on_id)
        self.reverse_adjacency[depends_on_id].add(dependent_id)

        edge = DependencyEdge(
            dependent_id=dependent_id,
            depends_on_id=depends_on_id,
            dependency_type=dependency_type,
            metadata=metadata or {}
        )
        self.edges.append(edge)

    def detect_cycles(self) -> List[List[str]]:
        """
        Detects directed cycles using depth-first search.
        Returns a list of cycle paths if found.
        """
        visited: Set[str] = set()
        rec_stack: Set[str] = set()
        path: List[str] = []
        cycles: List[List[str]] = []

        def dfs(node: str) -> None:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in self.adjacency.get(node, set()):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in rec_stack:
                    # Cycle found
                    cycle_start = path.index(neighbor)
                    cycles.append(path[cycle_start:] + [neighbor])

            path.pop()
            rec_stack.remove(node)

        for n in sorted(self.nodes.keys()):
            if n not in visited:
                dfs(n)

        return cycles

    def find_missing_dependencies(self) -> List[DependencyEdge]:
        """Identifies edges where the target dependency is not registered in nodes."""
        missing = []
        for edge in self.edges:
            if edge.depends_on_id not in self.nodes:
                missing.append(edge)
        return missing

    def validate(self) -> None:
        """
        Validates graph integrity:
        1. Fails closed on circular references.
        2. Fails closed on missing mandatory dependencies.
        """
        cycles = self.detect_cycles()
        if cycles:
            raise CircularDependencyError(cycles[0])

        missing = self.find_missing_dependencies()
        mandatory_missing = [e for e in missing if e.dependency_type == DependencyType.MANDATORY]
        if mandatory_missing:
            raise MissingDependencyError(mandatory_missing)

    def resolve_order(self) -> List[str]:
        """
        Computes deterministic topological execution order.
        Dependencies appear before dependents.
        Uses Kahn's algorithm with sorted tie-breaking for reproducibility across runs.
        """
        self.validate()

        # In Kahn's algorithm for execution order:
        # A depends on B means B must execute before A.
        # Indegree represents the number of registered dependencies a node is waiting on.
        node_set = set(self.nodes)
        in_degree: Dict[str, int] = {
            n: len(self.adjacency.get(n, set()) & node_set)
            for n in self.nodes
        }

        # Nodes with 0 dependencies ready to run first
        ready = sorted([n for n, deg in in_degree.items() if deg == 0])
        resolved: List[str] = []

        while ready:
            curr = ready.pop(0)
            resolved.append(curr)

            # For each dependent that was waiting on curr
            for dependent in sorted(self.reverse_adjacency.get(curr, set())):
                if dependent in in_degree:
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        ready.append(dependent)
                        ready.sort()

        if len(resolved) != len(self.nodes):
            remaining = set(self.nodes) - set(resolved)
            raise CircularDependencyError(list(remaining))

        return resolved

    def get_transitive_dependencies(self, resource_id: str) -> Set[str]:
        """Returns all transitive dependencies required by a given resource."""
        visited: Set[str] = set()

        def dfs(node: str):
            for dep in self.adjacency.get(node, set()):
                if dep not in visited:
                    visited.add(dep)
                    dfs(dep)

        dfs(resource_id)
        return visited
