"""
Real-time Progress Tracker for Threat Modeling Analysis
"""

from typing import Dict, Optional
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel
import structlog

logger = structlog.get_logger()


class AnalysisProgress(BaseModel):
    """Progress state for an analysis"""
    model_id: UUID
    status: str  # "in_progress", "completed", "failed"
    current_phase: str
    current_agent: Optional[str] = None
    progress_percentage: float = 0.0
    started_at: datetime
    completed_phases: list[str] = []
    total_phases: int = 5  # DFD, STRIDE, OWASP+Threats, Parallel Agents, CVE
    message: str = ""


class ProgressTracker:
    """
    Track analysis progress in real-time for UI updates
    """

    def __init__(self):
        self.progress_db: Dict[UUID, AnalysisProgress] = {}
        self.logger = structlog.get_logger().bind(component="progress_tracker")

    def start_analysis(self, model_id: UUID) -> None:
        """Start tracking a new analysis"""
        self.progress_db[model_id] = AnalysisProgress(
            model_id=model_id,
            status="in_progress",
            current_phase="Initializing",
            started_at=datetime.now(),
            progress_percentage=0.0,
            message="Starting threat modeling analysis..."
        )
        self.logger.info("Started tracking analysis", model_id=str(model_id))

    def update_phase(
        self,
        model_id: UUID,
        phase: str,
        agent: Optional[str] = None,
        message: str = ""
    ) -> None:
        """Update the current phase of analysis"""
        if model_id not in self.progress_db:
            self.logger.warning("Analysis not found in progress tracker", model_id=str(model_id))
            return

        progress = self.progress_db[model_id]
        progress.current_phase = phase
        progress.current_agent = agent
        progress.message = message

        # Update progress percentage based on phase
        phase_progress = {
            "Building DFD": 20.0,
            "STRIDE Analysis": 40.0,
            "OWASP Analysis": 60.0,
            "Parallel Agents": 80.0,
            "CVE Enrichment": 90.0,
            "Finalizing": 95.0,
            "Complete": 100.0
        }

        progress.progress_percentage = phase_progress.get(phase, progress.progress_percentage)

        self.logger.info(
            "Updated analysis phase",
            model_id=str(model_id),
            phase=phase,
            agent=agent,
            progress=f"{progress.progress_percentage}%"
        )

    def complete_phase(self, model_id: UUID, phase: str) -> None:
        """Mark a phase as completed"""
        if model_id not in self.progress_db:
            return

        progress = self.progress_db[model_id]
        if phase not in progress.completed_phases:
            progress.completed_phases.append(phase)

    def complete_analysis(self, model_id: UUID, success: bool = True) -> None:
        """Mark analysis as complete"""
        if model_id not in self.progress_db:
            return

        progress = self.progress_db[model_id]
        progress.status = "completed" if success else "failed"
        progress.current_phase = "Complete"
        progress.progress_percentage = 100.0
        progress.message = "Analysis completed successfully!" if success else "Analysis failed"

        self.logger.info("Analysis complete", model_id=str(model_id), success=success)

    def get_progress(self, model_id: UUID) -> Optional[AnalysisProgress]:
        """Get current progress for an analysis"""
        return self.progress_db.get(model_id)

    def cleanup(self, model_id: UUID) -> None:
        """Remove progress tracking for completed analysis"""
        if model_id in self.progress_db:
            del self.progress_db[model_id]


# Global progress tracker instance
progress_tracker = ProgressTracker()
