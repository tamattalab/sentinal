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
    agentNotes: str = ""
    reply: str = ""
