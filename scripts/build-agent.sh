#!/usr/bin/env bash
# build-agent.sh — Build or split the SpyCloud SCORCH Agent YAML
#
# Usage:
#   ./scripts/build-agent.sh build   — Concatenate modular files into SpyCloud_Agent.yaml
#   ./scripts/build-agent.sh split   — Split SpyCloud_Agent.yaml into modular files
#
# The monolithic SpyCloud_Agent.yaml (~6000+ lines) is the file that Security
# Copilot actually consumes. This script lets maintainers work with smaller,
# focused files and then assemble the final artifact.
#
# Module layout (copilot/agent-modules/):
#   01-descriptor.yaml    — Descriptor block (name, settings, metadata)
#   02-main-agent.yaml    — Primary SpyCloudInvestigationAgent skill group
#   03-subagents.yaml     — All 25 sub-agent skill groups
#   04-agent-definitions.yaml — AgentDefinitions routing block

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_FILE="$REPO_ROOT/copilot/SpyCloud_Agent.yaml"
MODULES_DIR="$REPO_ROOT/copilot/agent-modules"

cmd="${1:-help}"

case "$cmd" in
  split)
    echo "Splitting $AGENT_FILE into modular files..."
    mkdir -p "$MODULES_DIR"

    total_lines=$(wc -l < "$AGENT_FILE")

    # Find section boundaries
    skillgroups_line=$(grep -n '^SkillGroups:' "$AGENT_FILE" | head -1 | cut -d: -f1)
    agentdefs_line=$(grep -n '^AgentDefinitions:' "$AGENT_FILE" | head -1 | cut -d: -f1)

    # Find the first sub-agent (second "  - Name:" after SkillGroups that contains "Agent")
    # The main agent is the first skill group entry
    first_subagent_line=$(awk -v start="$skillgroups_line" '
      NR > start && /^  - Name:/ && /Agent/ { count++; if (count == 2) { print NR; exit } }
    ' "$AGENT_FILE")

    if [ -z "$skillgroups_line" ] || [ -z "$agentdefs_line" ]; then
      echo "ERROR: Could not find expected section markers in $AGENT_FILE"
      exit 1
    fi

    # 01-descriptor.yaml: line 1 to (SkillGroups - 1)
    sed -n "1,$((skillgroups_line - 1))p" "$AGENT_FILE" > "$MODULES_DIR/01-descriptor.yaml"
    echo "  Created 01-descriptor.yaml (lines 1-$((skillgroups_line - 1)))"

    # 02-main-agent.yaml: SkillGroups line through (first_subagent - 1)
    if [ -n "$first_subagent_line" ]; then
      sed -n "${skillgroups_line},$((first_subagent_line - 1))p" "$AGENT_FILE" > "$MODULES_DIR/02-main-agent.yaml"
      echo "  Created 02-main-agent.yaml (lines ${skillgroups_line}-$((first_subagent_line - 1)))"

      # 03-subagents.yaml: first_subagent through (AgentDefinitions - 1)
      sed -n "${first_subagent_line},$((agentdefs_line - 1))p" "$AGENT_FILE" > "$MODULES_DIR/03-subagents.yaml"
      echo "  Created 03-subagents.yaml (lines ${first_subagent_line}-$((agentdefs_line - 1)))"
    else
      # No sub-agents found; put everything in 02-main-agent.yaml
      sed -n "${skillgroups_line},$((agentdefs_line - 1))p" "$AGENT_FILE" > "$MODULES_DIR/02-main-agent.yaml"
      echo "  Created 02-main-agent.yaml (lines ${skillgroups_line}-$((agentdefs_line - 1)))"
      touch "$MODULES_DIR/03-subagents.yaml"
      echo "  Created 03-subagents.yaml (empty — no sub-agents found)"
    fi

    # 04-agent-definitions.yaml: AgentDefinitions to end
    sed -n "${agentdefs_line},${total_lines}p" "$AGENT_FILE" > "$MODULES_DIR/04-agent-definitions.yaml"
    echo "  Created 04-agent-definitions.yaml (lines ${agentdefs_line}-${total_lines})"

    echo ""
    echo "Split complete. Modules in: $MODULES_DIR/"
    ls -la "$MODULES_DIR/"
    ;;

  build)
    echo "Building $AGENT_FILE from modular files..."

    if [ ! -d "$MODULES_DIR" ]; then
      echo "ERROR: Module directory not found: $MODULES_DIR"
      echo "Run '$0 split' first to create modular files."
      exit 1
    fi

    # Verify all required modules exist
    for mod in 01-descriptor.yaml 02-main-agent.yaml 03-subagents.yaml 04-agent-definitions.yaml; do
      if [ ! -f "$MODULES_DIR/$mod" ]; then
        echo "ERROR: Missing module: $MODULES_DIR/$mod"
        exit 1
      fi
    done

    # Concatenate modules in order
    cat \
      "$MODULES_DIR/01-descriptor.yaml" \
      "$MODULES_DIR/02-main-agent.yaml" \
      "$MODULES_DIR/03-subagents.yaml" \
      "$MODULES_DIR/04-agent-definitions.yaml" \
      > "$AGENT_FILE"

    line_count=$(wc -l < "$AGENT_FILE")
    echo "Build complete: $AGENT_FILE ($line_count lines)"
    ;;

  help|*)
    echo "Usage: $0 {build|split}"
    echo ""
    echo "  split  — Split SpyCloud_Agent.yaml into modular files in copilot/agent-modules/"
    echo "  build  — Concatenate modular files back into SpyCloud_Agent.yaml"
    echo ""
    echo "Workflow:"
    echo "  1. Run '$0 split' to create modular files"
    echo "  2. Edit individual module files as needed"
    echo "  3. Run '$0 build' to reassemble the monolithic YAML"
    echo "  4. Commit both the modules and the built SpyCloud_Agent.yaml"
    ;;
esac
