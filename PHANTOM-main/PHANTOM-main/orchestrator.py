"""
PHANTOM Orchestrator — ReAct (Reasoning + Acting) loop.
Plan -> Act -> Observe -> Reflect -> Replan
All decisions made by LLM at runtime. Nothing hardcoded.
"""
import json
import time
import uuid
import os
from dotenv import load_dotenv

from llm import generate
from memory.store import PhantomMemory
from models import OrchestratorPlan
from guardrails import validate_action, SecurityViolation
from agents.recon import ReconAgent
from agents.threat_model import ThreatModelAgent
from agents.exploit_engine import ExploitEngine
from agents.patch_agent import PatchAgent
from agents.report_agent import ReportAgent
import ui

load_dotenv()


class PhantomOrchestrator:
    """
    ReAct loop orchestrator.
    Plan -> Act -> Observe -> Reflect -> Replan
    All decisions made by LLM at runtime — nothing hardcoded.
    """

    def __init__(self):
        self.session_id = f"phantom-{uuid.uuid4().hex[:8]}"
        self.memory = PhantomMemory(self.session_id)

        # Agent registry
        self.agents = {
            "recon":          ReconAgent(self.memory),
            "threat_model":   ThreatModelAgent(self.memory),
            "exploit_engine": ExploitEngine(self.memory),
            "patch_agent":    PatchAgent(self.memory),
            "report_agent":   ReportAgent(self.memory),
        }

        self.results = {}
        self.thought_trace = []

    def run(self, target: str, target_path: str = None) -> dict:
        """Main entry point. Returns full assessment report."""
        start_time = time.time()

        ui.print_banner(self.session_id, target, target_path)

        # ReAct loop — LLM decides the sequence
        max_cycles = 8
        cycle = 0

        state = {
            "target":      target,
            "target_path": target_path,
            "completed":   [],
            "session_id":  self.session_id
        }

        while cycle < max_cycles:
            cycle += 1

            # PLAN: ask LLM what to do next
            next_action = self._plan(state)

            if next_action.action == "done":
                ui.orchestrator_done(next_action.reason or "All agents complete")
                break

            agent_name = next_action.agent

            # Log thought
            self.thought_trace.append({
                "cycle":   cycle,
                "thought": next_action.reasoning,
                "action":  next_action.action,
                "agent":   agent_name
            })

            ui.orchestrator_cycle(cycle, next_action.reasoning)

            # ACT: run the selected agent
            try:
                validate_action("orchestrator", f"run_agent {agent_name}")
                result = self._act(agent_name, state)
                self.results[agent_name] = result
                state["completed"].append(agent_name)

                # OBSERVE + REFLECT: update state with result summary
                state[agent_name] = self._summarise_result(agent_name, result)

            except SecurityViolation as e:
                ui.guardrail_block("action_validator", str(e))
                state[f"{agent_name}_error"] = str(e)
                state["completed"].append(f"{agent_name}_blocked")
            except Exception as e:
                ui.agent_error(agent_name, f"Failed: {e}")
                state[f"{agent_name}_error"] = str(e)
                state["completed"].append(f"{agent_name}_failed")

        duration = time.time() - start_time

        # Final report
        self.results["duration"] = duration
        report = self.agents["report_agent"].run(
            {
                "recon":        self.results.get("recon", {}),
                "threat_model": self.results.get("threat_model", {}),
                "exploit":      self.results.get("exploit_engine", {}),
                "patches":      self.results.get("patch_agent", {}),
                "duration":     duration
            },
            self.session_id
        )

        report["thought_trace"] = self.thought_trace
        return report

    def _plan(self, state: dict) -> OrchestratorPlan:
        """
        PLAN step of ReAct loop.
        LLM decides what agent to run next based on current state.
        Response validated with Pydantic — no silent coercion.
        """
        completed = state.get("completed", [])

        prompt = f"""You are the PHANTOM orchestrator running a security assessment.

Current state:
- Target: {state.get('target')}
- Codebase path: {state.get('target_path', 'not provided')}
- Completed agents: {completed}
- Recon results available: {'recon' in completed}
- Threat model available: {'threat_model' in completed}
- Exploit results available: {'exploit_engine' in completed}
- Patches available: {'patch_agent' in completed}

Available agents: recon, threat_model, exploit_engine, patch_agent

Agent dependencies:
- threat_model requires: recon
- exploit_engine requires: recon AND threat_model AND codebase path
- patch_agent requires: exploit_engine

Decide what to do next. If all key agents have run, respond with action: "done".

Respond ONLY in this JSON format (no markdown, no extra text):
{{
  "action": "run_agent" or "done",
  "agent": "agent_name or null",
  "reasoning": "why this agent should run now",
  "reason": "if done, why assessment is complete"
}}"""

        text = generate(prompt)
        text = text.replace("```json", "").replace("```", "").strip()

        try:
            parsed = json.loads(text)
            return OrchestratorPlan(**parsed)
        except Exception:
            # Fallback: pick next unrun agent in order
            order = ["recon", "threat_model", "exploit_engine", "patch_agent"]
            for agent in order:
                if agent not in completed:
                    return OrchestratorPlan(
                        action="run_agent",
                        agent=agent,
                        reasoning=f"Fallback: running {agent} (LLM response unparseable)",
                        reason=""
                    )
            return OrchestratorPlan(
                action="done",
                agent=None,
                reasoning="All agents complete",
                reason="All agents have run — generating report"
            )

    def _act(self, agent_name: str, state: dict) -> dict:
        """ACT step — run the selected agent."""
        target = state["target"]
        target_path = state.get("target_path")

        if agent_name == "recon":
            return self.agents["recon"].run(target, target_path)

        elif agent_name == "threat_model":
            return self.agents["threat_model"].run(self.results["recon"])

        elif agent_name == "exploit_engine":
            if not target_path:
                return {"confirmed": [], "unconfirmed": [],
                        "note": "No codebase path — skipping static analysis"}
            return self.agents["exploit_engine"].run(
                self.results["threat_model"], target_path
            )

        elif agent_name == "patch_agent":
            return self.agents["patch_agent"].run(
                self.results["exploit_engine"], self.session_id
            )

        return {}

    def _summarise_result(self, agent_name: str, result: dict) -> dict:
        """REFLECT step — summarise result for next planning cycle."""
        if agent_name == "recon":
            ports = result.get("network_surface", {}).get("open_ports", [])
            return {
                "port_count": len(ports),
                "services": [p["service"] for p in ports],
                "has_codebase": bool(result.get("code_surface", {}).get("file_count", 0))
            }

        elif agent_name == "threat_model":
            return {
                "finding_count": result.get("total_attack_paths", 0),
                "highest_risk": result.get("highest_risk", {}).get("technique_id", "none")
            }

        elif agent_name == "exploit_engine":
            return {
                "confirmed": len(result.get("confirmed", [])),
                "unconfirmed": len(result.get("unconfirmed", []))
            }

        elif agent_name == "patch_agent":
            return {
                "patches": len(result.get("patches", [])),
                "all_cleared": result.get("all_cleared", False)
            }

        return {}
