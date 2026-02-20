from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class Message(BaseModel):
    sender: str = ""
    text: str = ""
    timestamp: Any = 0  # Accept int (epoch) or str (ISO format)


class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"


class AnalyzeRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[Message]] = []
    metadata: Optional[Metadata] = None


class ExtractedIntelligence(BaseModel):
    phoneNumbers: List[str] = []
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    emailAddresses: List[str] = []
    caseIds: List[str] = []
    policyNumbers: List[str] = []
    orderNumbers: List[str] = []
    suspiciousKeywords: List[str] = []  # Competition rubric field


class BehavioralIntelligence(BaseModel):
    """Tracks scammer behavioral patterns across the conversation."""
    escalationPattern: str = "none"       # none → gradual → aggressive → desperate
    manipulationTypes: List[str] = []     # fear, authority, urgency, greed, etc.
    redFlagsIdentified: List[str] = []    # Human-readable red flag descriptions
    probingQuestionsAsked: List[str] = [] # Questions agent used to extract intel
    scammerProfile: str = ""              # Summary of scammer behavior
    tacticsUsed: List[str] = []           # Credential Theft, KYC Impersonation, etc.


class FraudAnalysis(BaseModel):
    """Output from the Gaussian Naïve Bayes JP Morgan fraud detection model."""
    fraudLabel: str = "fraudulent"          # 'fraudulent' or 'normal'
    fraudProbability: float = 0.0           # 0.0–1.0 model output
    transactionRiskScore: int = 0           # 0–100 human-readable risk
    riskLevel: str = "HIGH"                 # LOW / MEDIUM / HIGH / CRITICAL
    features: Dict[str, Any] = Field(default_factory=dict)   # 4 input features used
    modelInfo: str = "GaussianNB (JP Morgan synthetic, ~79.5% accuracy)"


class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int = 0
    totalMessagesExchanged: int = 0


class AnalyzeResponse(BaseModel):
    sessionId: str
    status: str = "success"
    scamDetected: bool = True
    scamType: Optional[str] = None
    confidenceLevel: float = 0.85
    totalMessagesExchanged: int = 0
    engagementDurationSeconds: int = 0
    extractedIntelligence: ExtractedIntelligence = Field(default_factory=ExtractedIntelligence)
    engagementMetrics: EngagementMetrics = Field(default_factory=EngagementMetrics)
    behavioralIntelligence: BehavioralIntelligence = Field(default_factory=BehavioralIntelligence)
    fraudAnalysis: FraudAnalysis = Field(default_factory=FraudAnalysis)  # GNB model output
    agentNotes: str = ""
    redFlags: List[str] = []
    probingQuestions: List[str] = []
    reply: str = ""
