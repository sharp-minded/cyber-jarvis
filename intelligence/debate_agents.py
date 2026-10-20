"""
intelligence/debate_agents.py - Multi-agent debate + reflection

Two patterns:
- DebateOrchestrator: multiple agents argue, judge picks winner
- ReflexionAgent: self-critique + improve
"""

import re
from typing import Dict, List
from rich.console import Console
from rich.panel import Panel

from core.agents import BaseAgent

console = Console()


class DebateOrchestrator:
    """
    Three-agent debate: Attacker vs Defender vs Judge.

    Useful for: choosing best exploit, deciding risk, evaluating approaches.
    """

    def __init__(self):
        self.attacker = BaseAgent(
            "Attacker",
            "You are an aggressive red teamer. "
            "Argue FOR each option. Give concrete reasons why it will succeed. "
            "Be specific about techniques and expected outcomes.",
        )
        self.defender = BaseAgent(
            "Defender",
            "You are a defensive security expert. "
            "Argue AGAINST each option. Point out risks, detection likelihood, "
            "legal concerns, and failure modes.",
        )
        self.judge = BaseAgent(
            "Judge",
            "You are a neutral judge. Given pro and con arguments, "
            "pick the BEST option. "
            "Output format (STRICT):\n"
            "WINNER: <option text>\n"
            "REASON: <short reasoning>\n"
            "CONFIDENCE: <0-100>",
        )

    def debate(
        self,
        question: str,
        options: List[str],
        context: str = "",
    ) -> Dict:
        """Run debate and return winner."""
        if not options:
            return {"winner": "", "reason": "No options", "confidence": 0, "debates": []}

        console.print(Panel(
            f"[bold]Debating {len(options)} options[/bold]\n"
            f"Question: {question}",
            border_style="yellow",
        ))

        debates = []
        for opt in options:
            console.print(f"[cyan][*] Debating: {opt[:60]}...[/cyan]")

            pro = self.attacker.think(
                f"Question: {question}\n"
                f"Option: {opt}\n"
                f"Context: {context}\n\n"
                f"Argue FOR this option. Give 3-5 strong reasons."
            )
            con = self.defender.think(
                f"Question: {question}\n"
                f"Option: {opt}\n"
                f"Context: {context}\n\n"
                f"Argue AGAINST this option. Give 3-5 strong reasons."
            )
            debates.append({"option": opt, "pro": pro, "con": con})

        # Build summary for judge
        summary = "\n\n".join([
            f"### Option: {d['option']}\n"
            f"PRO:\n{d['pro']}\n\n"
            f"CON:\n{d['con']}"
            for d in debates
        ])

        verdict = self.judge.think(
            f"Question: {question}\n"
            f"Context: {context}\n\n"
            f"Debates:\n{summary}\n\n"
            f"Which option wins? Output WINNER, REASON, CONFIDENCE."
        )

        # Parse verdict
        winner_match = re.search(r"WINNER:\s*(.+)", verdict)
        reason_match = re.search(r"REASON:\s*(.+)", verdict)
        conf_match = re.search(r"CONFIDENCE:\s*(\d+)", verdict)

        winner = winner_match.group(1).strip() if winner_match else options[0]
        reason = reason_match.group(1).strip() if reason_match else ""
        confidence = int(conf_match.group(1)) if conf_match else 50

        console.print(Panel(
            f"[bold green]Winner: {winner[:100]}[/bold green]\n"
            f"Reason: {reason[:300]}\n"
            f"Confidence: {confidence}%",
            border_style="green",
        ))

        return {
            "winner": winner,
            "reason": reason,
            "confidence": confidence,
            "debates": debates,
            "raw_verdict": verdict,
        }


class ReflexionAgent(BaseAgent):
    """
    Self-critique and improve loop.

    Usage:
        reflexion = ReflexionAgent()
        result = reflexion.reflect("Analyze code", original_output)
        if result["needs_improvement"]:
            use result["improved"]
    """

    def __init__(self):
        super().__init__(
            "Reflexion",
            "You critically review outputs. Find mistakes, gaps, improvements. "
            "If output is correct, say 'NO_IMPROVEMENT_NEEDED'.",
        )

    def reflect(self, task: str, output: str) -> Dict:
        """
        Critique output and provide improved version if needed.
        """
        critique = self.think(
            f"Task: {task}\n\n"
            f"Output:\n{output[:3000]}\n\n"
            f"Critique this output. What's wrong, missing, or could be better? "
            f"If perfect, say 'NO_IMPROVEMENT_NEEDED'."
        )

        needs_improvement = "NO_IMPROVEMENT_NEEDED" not in critique.upper()

        if needs_improvement:
            improved = self.think(
                f"Task: {task}\n\n"
                f"Original output:\n{output[:3000]}\n\n"
                f"Critique:\n{critique}\n\n"
                f"Provide the IMPROVED version. Address all critique points."
            )
        else:
            improved = output

        return {
            "needs_improvement": needs_improvement,
            "critique": critique,
            "improved": improved,
        }


# ─── CLI test ─────────────────────────────────────────────

if __name__ == "__main__":
    debate = DebateOrchestrator()
    result = debate.debate(
        question="Which exploit to use?",
        options=["Metasploit SMB", "Manual Python script"],
        context="Target is Windows Server 2019 with SMB exposed",
    )
    print(result)