"""
LCS Dependency Resolver (Phase 2B)
==================================
Builds multi-resource dependency graphs from hydrated capabilities and computes
deterministic resolution orders with cycle and missing dependency enforcement.
"""

from typing import Dict, Any, List, Optional
from .models import ResourceType, DependencyType, DependencyNode
from .graph import DependencyGraph, DependencyError
from ..hydration.models import HydratedCapability


class DependencyResolver:
    """
    Coordinates multi-resource dependency resolution across skills, tools, scripts, and workflows.
    """

    @classmethod
    def build_graph_for_capabilities(
        cls,
        capabilities: List[HydratedCapability]
    ) -> DependencyGraph:
        """Constructs a DependencyGraph from a list of hydrated capabilities."""
        graph = DependencyGraph()

        # 1. Register root capability nodes
        for cap in capabilities:
            node = DependencyNode(
                resource_id=cap.capability_urn,
                resource_type=ResourceType.SKILL,
                display_name=cap.name,
                is_mandatory=True,
                metadata=cap.provenance
            )
            graph.add_node(node)

            # 2. Register auxiliary assets as nodes & edges
            for rel_path, aux in cap.auxiliary_files.items():
                aux_id = f"{cap.capability_urn}:{rel_path}"
                ext = aux.relative_path.split(".")[-1].lower() if "." in aux.relative_path else ""
                rtype = ResourceType.DOCUMENTATION
                if ext in ("py", "sh", "bash", "js", "ts"):
                    rtype = ResourceType.SCRIPT
                elif ext in ("j2", "jinja", "template"):
                    rtype = ResourceType.TEMPLATE

                aux_node = DependencyNode(
                    resource_id=aux_id,
                    resource_type=rtype,
                    display_name=rel_path,
                    is_mandatory=True,
                    metadata={"path": aux.absolute_path, "digest": aux.digest}
                )
                graph.add_node(aux_node)
                # The capability depends on its auxiliary file
                graph.add_dependency(
                    dependent_id=cap.capability_urn,
                    depends_on_id=aux_id,
                    dependency_type=DependencyType.MANDATORY
                )

            # 3. Register declared dependencies
            for dep in cap.dependencies:
                dep_type = DependencyType.MANDATORY if dep.is_mandatory else DependencyType.OPTIONAL
                try:
                    res_type = ResourceType(dep.resource_type)
                except ValueError:
                    res_type = ResourceType.SKILL

                # If dependent target is an auxiliary file
                norm_target = dep.target_urn_or_path.replace("\\", "/").lstrip("./")
                if norm_target in cap.auxiliary_files:
                    dep_node_id = f"{cap.capability_urn}:{norm_target}"
                else:
                    dep_node_id = dep.target_urn_or_path

                if dep_node_id not in graph.nodes:
                    graph.add_node(DependencyNode(
                        resource_id=dep_node_id,
                        resource_type=res_type,
                        display_name=dep.name,
                        is_mandatory=dep.is_mandatory
                    ))

                graph.add_dependency(
                    dependent_id=cap.capability_urn,
                    depends_on_id=dep_node_id,
                    dependency_type=dep_type
                )

        return graph

    @classmethod
    def resolve_execution_order(cls, capabilities: List[HydratedCapability]) -> List[str]:
        """Builds graph and computes deterministic topological execution sequence."""
        graph = cls.build_graph_for_capabilities(capabilities)
        return graph.resolve_order()
