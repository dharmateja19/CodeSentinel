
from app.agent.llm import generate_analysis

result = generate_analysis(
    "Explain why hardcoded passwords are a security risk. "
    "Answer in three sentences."
)

print("Provider:", result["provider"])
print("Response:", result["response"])
