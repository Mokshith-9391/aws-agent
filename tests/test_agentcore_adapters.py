from unittest.mock import Mock

from agent.llm_client import BedrockLLMClient
from config.settings import Settings
from rag.bedrock_knowledge_service import BedrockKnowledgeService


def test_bedrock_llm_uses_converse_api():
    client = BedrockLLMClient("amazon.nova-lite-v1:0", "ap-south-1")
    client._client = Mock(converse=Mock(return_value={"output": {"message": {"content": [{"text": "ok"}]}}}))
    assert client.generate("system", "question") == "ok"
    assert client._client.converse.call_args.kwargs["modelId"] == "amazon.nova-lite-v1:0"


def test_knowledge_base_maps_retrieval_to_grounded_citations():
    settings = Settings(BEDROCK_KNOWLEDGE_BASE_ID="kb-123")
    client = Mock(retrieve=Mock(return_value={"retrievalResults": [{
        "content": {"text": "approved policy"}, "score": 0.9,
        "location": {"s3Location": {"uri": "s3://docs/policy.md"}}, "metadata": {"department": "Security"},
    }]}))
    answer = BedrockKnowledgeService(settings=settings, client=client).query("policy")
    assert answer.grounded and answer.citations[0].filename == "policy.md"

